#
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
import boto3, json, time, os, logging, botocore, uuid
from crhelper import CfnResource
from botocore.exceptions import ClientError

# Set default Sid for SNS topic policy
if 'sysdig_sns_sid' in os.environ:
    sysdig_sns_sid = os.environ['sysdig_sns_sid']
else:
    sysdig_sns_sid = 'SysdigCTPolicy'

# Set default Sid for KMS key policy
if 'sysdig_kms_sid' in os.environ:
    sysdig_kms_sid = os.environ['sysdig_kms_sid']
else:
    sysdig_kms_sid = 'SysdigCTKMSPolicy'
    
# Set default role name to assume
if 'sysdig_ct_assume_role' in os.environ:
    sysdig_ct_assume_role = os.environ['sysdig_ct_assume_role']
else:
    sysdig_ct_assume_role = 'AWSControlTowerExecution'

# Set default CT baseline cloudtrail stackset
if 'sysdig_ct_cloudtrail_stackset' in os.environ:
    sysdig_ct_cloudtrail_stackset = os.environ['sysdig_ct_cloudtrail_stackset']
else:
    sysdig_ct_cloudtrail_stackset = 'AWSControlTowerBP-BASELINE-CLOUDTRAIL'

# Set logging verbosity
logger = logging.getLogger()
if 'log_level' in os.environ:
    logger.setLevel(os.environ['log_level'])
    logger.info("Log level set to %s" % logger.getEffectiveLevel())
else:
    logger.setLevel(logging.INFO)
logging.getLogger('boto3').setLevel(logging.CRITICAL)
logging.getLogger('botocore').setLevel(logging.CRITICAL)
session = boto3.Session()

helper = CfnResource(json_logging=False, log_level='INFO', boto_level='CRITICAL', sleep_on_delete=15)
callback_helper = CfnResource(json_logging=False, log_level='INFO', boto_level='CRITICAL', sleep_on_delete=15)

# receive call back from log archive stackset instance and add Fargate task role to KMS key policy
@callback_helper.create
@callback_helper.update
def callback_create(event, context):
    try:
        fargateTaskRole = event['ResourceProperties']['TaskRole']
        logger.info("Modifying AWS Control Tower CloudTrail KMS key policy with task role {}".format(fargateTaskRole))
        cloudTrailKMSArn = ct_cloudtrail_kms_handler(fargateTaskRole)
        if cloudTrailKMSArn:
            logger.info("Success - KMS key policy")
    except Exception as describeException:
        logger.error('Failed on modifying AWS Control Tower CloudTrail KMS Key policy, check if KMS key exist and re-run')
    return None #Generate random ID

@callback_helper.delete
def callback_delete(event, context):
    logger.info("Log Archive StackSet instances delete initiated")
    return None #Generate random ID

@helper.create
@helper.update
# This module perform the following:
# 1. attempt to create stackset if one does not exist
# 2. attempt to deploy stackset instance to target accounts
# 3. modify AWS CT CloudTrail SNS policy to allow SQS to subscribe
# 4. modify AWS CT CloudTrail KMS policy to allow decryption of cloudtrail messages
def create(event, context):
    try:
        managementAccountId = context.invoked_function_arn.split(":")[4]
        regionName = context.invoked_function_arn.split(":")[3]
        auditAccount, logArchiveAccount, cloudTrailSNSTopic = ct_core_account_handler(regionName)
        
        try:
            logger.info("Modifying AWS Control Tower CloudTrail SNS policy: {}".format(cloudTrailSNSTopic))
            if ct_sns_topic_handler(auditAccount, cloudTrailSNSTopic, logArchiveAccount):
                logger.info("Success - SNS policy {} modified".format(cloudTrailSNSTopic))
        except Exception as describeException:
            logger.error('Failed on modifying AWS Control Tower CloudTrail SNS policy: {}'.format(cloudTrailSNSTopic))
        
        try:
            logger.info("Searching AWS Control Tower CloudTrail KMS key policy")
            cloudTrailKMSArn = ct_cloudtrail_kms_finder()
            if cloudTrailKMSArn:
                logger.info("Success - CT CloudTrail with KMS - callback required")
            else:
                logger.info("Success - CT CloudTrail without KMS - callback not required")
                cloudTrailKMSArn = '' #set to empty string to allow stackset condition check
                
        except Exception as describeException:
            logger.error('Failed on modifying AWS Control Tower CloudTrail KMS Key policy, check if KMS key exist and re-run')
            
        try:
            logger.info("Start Sysdig CT StackSet operations")
            if ct_stackset_handler(regionName, managementAccountId, logArchiveAccount, auditAccount, cloudTrailSNSTopic, cloudTrailKMSArn):
                logger.info("Sysdig CT StackSet operations completed")
        except Exception as describeException:
            logger.error("Failed on Sysdig CT StackSet operations : {}".format(Exception))
    
    except Exception as describeException:
        logger.info('Unable to pull CT related metadata, canceling the remaining steps')

    return None #Generate random ID

@helper.delete
# This module perform the following:
# 1. attempt to delete stackset instances
# 2. attempt to delete stackset
def delete(event, context):
    logger.info("Delete StackSet Instances")
    deleteWaitTime = (int(context.get_remaining_time_in_millis()) - 100)/1000
    deleteSleepTime = 30
    try:
        stackSetName = os.environ['stackSetName']
        stackSetUrl = os.environ['stackSetUrl']
        managementAccountId = context.invoked_function_arn.split(":")[4]
        regionName = context.invoked_function_arn.split(":")[3]
        
        cloudFormation_client = session.client('cloudformation')
        cloudFormation_client.describe_stack_set(StackSetName=stackSetName)
        logger.info('Stack set {} exist'.format(stackSetName))
        
        paginator = cloudFormation_client.get_paginator('list_stack_instances')
        pageIterator = paginator.paginate(StackSetName= stackSetName)
        stackSetList = []
        accountList = []
        regionList = []
        for page in pageIterator:
            if 'Summaries' in page:
                stackSetList.extend(page['Summaries'])
        for instance in stackSetList:
            accountList.append(instance['Account'])
            regionList.append(instance['Region'])
        regionList = list(set(regionList))
        accountList = list(set(accountList))
        logger.info("StackSet instances found in region(s): {}".format(regionList))
        logger.info("StackSet instances found in account(s): {}".format(accountList))
        
        try:
            if len(accountList) > 0:
                response = cloudFormation_client.delete_stack_instances(
                    StackSetName=stackSetName,
                    Accounts=accountList,
                    Regions=regionList,
                    RetainStacks=False)
                logger.info(response)
                
                status = cloudFormation_client.describe_stack_set_operation(
                    StackSetName=stackSetName,
                    OperationId=response['OperationId'])
                    
                while status['StackSetOperation']['Status'] == 'RUNNING' and deleteWaitTime>0:
                    time.sleep(deleteSleepTime)
                    deleteWaitTime=deleteWaitTime-deleteSleepTime
                    status = cloudFormation_client.describe_stack_set_operation(
                        StackSetName=stackSetName,
                        OperationId=response['OperationId'])
                    logger.info("StackSet instance delete status {}".format(status))
            
            try:
                response = cloudFormation_client.delete_stack_set(StackSetName=stackSetName)
                logger.info("StackSet template delete status {}".format(response))
            except Exception as stackSetException:
                logger.warning("Problem occured while deleting, StackSet still exist : {}".format(stackSetException))
                
        except Exception as describeException:
            logger.error(describeException)

    except Exception as describeException:
        logger.error(describeException)
        return None
    
    return None #Generate random ID


def get_secret_value(secret_arn, key):
    secretClient = session.client('secretsmanager')
    try:
        secret_response = secretClient.get_secret_value(
            SecretId=secret_arn
        )
        if 'SecretString' in secret_response:
            secret = json.loads(secret_response['SecretString'])[key]
            return secret 
    
    except Exception as e:
        logger.error('Get Secret Failed: ' + str(e))
    
def generate_cft_params(keys, values):
    param_keys = ['ParameterKey', 'ParameterValue']
    param_vals = []
    cft_params = []
    for i in range(len(keys)):
        param_vals.append([keys[i], values[i]])
    for item in param_vals:
        cft_params.append(dict(zip(param_keys, item)))
    return cft_params

# This module perform the following:
# 1. Check if Sysdig stackset exist
# 2. If not exist, create new stackset
# 3. Add Log Archive account as stackset instance
def ct_stackset_handler(regionName, managementAccountId, logArchiveAccount, auditAccount, cloudTrailSNSTopic, cloudTrailKMSArn):
    try:
        stackSetName = os.environ['stackSetName']
        stackSetUrl = os.environ['stackSetUrl']
        sysdigSecureEndpoint = os.environ['sysdigSecureEndpoint']
        sysdigSecureSecretArn = os.environ['sysdigSecureSecret']
        callbackSNS = os.environ['callbackSNS']
        
        sysdigSecureSecret = get_secret_value(sysdigSecureSecretArn, 'Token')
        if not sysdigSecureSecret:
            raise Exception('Error trying to access / read secret credentials')
        
        try:
            cloudFormation_client = session.client('cloudformation')
            cloudFormation_client.describe_stack_set(StackSetName=stackSetName)
            logger.info('StackSet {} already exist'.format(stackSetName))
            helper.Data.update({"result": stackSetName})
            
        except Exception as describeException:
            logger.info('StackSet {} does not exist, creating it now.'.format(stackSetName))
            
            cloudFormation_client.create_stack_set(
                StackSetName=stackSetName,
                Description='Sysdig for Cloud - AWS Control Tower Edition',
                TemplateURL=stackSetUrl,
                Parameters=generate_cft_params(
                    keys=['SysdigSecureEndpoint', 'SysdigSecureAPIToken', 'CloudBenchDeploy', 'CloudConnectorDeploy','ECRImageScanningDeploy','ECSImageScanningDeploy','LogArchiveAccount','AuditAccount','ExistentCloudTrailSNSTopic', 'CloudTrailKMS', 'CallbackSNS'],
                    values=[sysdigSecureEndpoint, sysdigSecureSecret, 'No', 'Yes', 'No', 'No', logArchiveAccount, auditAccount, cloudTrailSNSTopic, cloudTrailKMSArn, callbackSNS]),
                Capabilities=[
                    'CAPABILITY_NAMED_IAM'
                ],
                AdministrationRoleARN='arn:aws:iam::' + managementAccountId + ':role/service-role/AWSControlTowerStackSetRole',
                ExecutionRoleName=sysdig_ct_assume_role)
            logger.info('StackSet {} created'.format(stackSetName))
    
        try:
            #check if there are any existing stackset operations
            cloudFormation_client.describe_stack_set(StackSetName=stackSetName)
            cloudFormationPaginator = cloudFormation_client.get_paginator('list_stack_set_operations')
            stackset_iterator = cloudFormationPaginator.paginate(
                StackSetName=stackSetName
            )
            stackset_ready = True
            for page in stackset_iterator:
                if 'Summaries' in page:
                    for operation in page['Summaries']:
                        if operation['Status'] in ('RUNNING', 'STOPPING'):
                            stackset_ready = False
                            break
                    if stackset_ready == False: 
                        break
            #launch stackset instance to log archive account on the CT main region
            if stackset_ready:
                response = cloudFormation_client.create_stack_instances(StackSetName=stackSetName, Accounts=[logArchiveAccount], Regions=[regionName])
                logger.info("StackSet instance created {}".format(response))
            else:
                logger.error("Unable to proceed, another StackSet operations underway, run stack update to retry")
            
        except cloudFormation_client.exceptions.StackSetNotFoundException as describeException:
            logger.error("Exception getting new stack set, {}".format(describeException))
            raise describeException
        
        return True
        
    except Exception as e:
        logger.error("CloudTrail StackSet Handler error: {}".format(e))
        return False
    
# This module perform the following:
# 1. Assume role to the Audit Account
# 2. If not exist, add topic policy to AWS CT CloudTrail SNS topic
def ct_sns_topic_handler(account, topic, log_archive):
    try:
        # Assume role to Audit account
        sts_client = session.client('sts')
        partition = sts_client.get_caller_identity()['Arn'].split(":")[1]
        response = sts_client.assume_role(
            RoleArn='arn:{}:iam::{}:role/{}'.format(
                    partition, account, sysdig_ct_assume_role),
            RoleSessionName=str(os.environ['stackSetName'] + '-' + account + 'CT-Integration')
        )
        
        audit_session = boto3.Session(
            aws_access_key_id=response['Credentials']['AccessKeyId'],
            aws_secret_access_key=response['Credentials']['SecretAccessKey'],
            aws_session_token=response['Credentials']['SessionToken']
        )
        
        # Locate SNS topic policy
        sns_client = audit_session.client('sns')
        sns_topic_attributes = sns_client.get_topic_attributes(TopicArn=topic)
        logger.debug(sns_topic_attributes['Attributes']['Policy'])
        sns_topic_policy = json.loads(sns_topic_attributes['Attributes']['Policy'])
        sysdig_ct_sid = next((item for item in sns_topic_policy['Statement'] if item['Sid'] == sysdig_sns_sid), False)
        
        # Modify SNS topic policy
        if sysdig_ct_sid:
            logger.info("Found SNS Topic policy: {}".format(sysdig_ct_sid))
        else:
            logger.info("Add new SNS Topic policy to {}".format(topic))
            new_sid = {
                "Sid": sysdig_sns_sid,
                "Effect": "Allow",
                "Principal": {
                    "AWS": "arn:aws:iam::{}:role/{}".format(log_archive, sysdig_ct_assume_role)
                },
                "Action": "sns:Subscribe",
                "Resource": topic
            }
            logger.debug("New SID: {}".format(new_sid))
            sns_topic_policy['Statement'].append(new_sid)
            logger.info("New SNS Topic Policy: {}".format(sns_topic_policy))
            sns_response = sns_client.set_topic_attributes(
                TopicArn=topic,
                AttributeName='Policy',
                AttributeValue=json.dumps(sns_topic_policy))
            logger.info("SNS Topic updated : {}".format(topic))
        
        return True
    except Exception as e:
        logger.error("SNS Topic Handler error: {}".format(e))
        return False


# This module perform the following:
# 1. Check if AWS CT CloudTrail uses KMS encryption
# 2. Ifexist, add permission for Fargate task to decrypt using CloudTrail KMS key
def ct_cloudtrail_kms_handler(allowed_role):
    try:
        # Check StackSet param
        cloudFormation_client = session.client('cloudformation')
        ct_cloudtrail_stackset = cloudFormation_client.describe_stack_set(StackSetName=sysdig_ct_cloudtrail_stackset)
        logger.info('AWS CT CloudTrail Baseline StackSet found: {}'.format(sysdig_ct_cloudtrail_stackset))
        
        # Add KMS key policy
        ct_cloudtrail_stackset_kms = next((item for item in ct_cloudtrail_stackset['StackSet']['Parameters'] if item['ParameterKey'] == 'KMSKeyArn'), False)
        if ct_cloudtrail_stackset_kms and ct_cloudtrail_stackset_kms['ParameterValue'] != 'NONE':
            ct_cloudtrail_kms_key = ct_cloudtrail_stackset_kms['ParameterValue']
            logger.info('AWS CT CloudTrail KMS Key found: {}'.format(ct_cloudtrail_kms_key))
            
            kms_client = session.client('kms')
            kms_policy = kms_client.get_key_policy(
                KeyId=ct_cloudtrail_kms_key,
                PolicyName='default')
            logger.debug(kms_policy['Policy'])
            ct_kms_policy = json.loads(kms_policy['Policy'])
            sysdig_ct_kms_sid = next((item for item in ct_kms_policy['Statement'] if item['Sid'] == sysdig_kms_sid), False)
            
            # Modify KMS Key policy
            if sysdig_ct_kms_sid:
                logger.info("No changes made, found KMS Key policy: {}".format(sysdig_ct_kms_sid))
                logger.warning("If you redeploy the stack, you need to manually delete the old KMS policy or replace it")
            else:
                logger.info("Add new KMS Key policy to {}".format(ct_cloudtrail_kms_key))
                new_sid = {
                    "Sid": sysdig_kms_sid,
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": allowed_role
                    },
                    "Action": "kms:Decrypt",
                    "Resource": "*"
                }
                logger.debug("New SID: {}".format(new_sid))
                ct_kms_policy['Statement'].append(new_sid)
                logger.info("New KMS key Policy: {}".format(ct_kms_policy))
                
                kms_response = kms_client.put_key_policy(
                    KeyId=ct_cloudtrail_kms_key,
                    PolicyName='default',
                    Policy=json.dumps(ct_kms_policy),
                    BypassPolicyLockoutSafetyCheck=False
                )
                logger.info("KMS key policy updated : {}".format(ct_cloudtrail_kms_key))
        else:
            logger.info('AWS CT CloudTrail KMS Key not found, skipping')
        return ct_cloudtrail_kms_key
    except Exception as e:
        logger.error("CloudTrail KMS Key Handler error: {}".format(e))
        return False

# This module perform the following:
# 1. Check if AWS CT CloudTrail uses KMS encryption
def ct_cloudtrail_kms_finder():
    try:
        # Check StackSet param
        cloudFormation_client = session.client('cloudformation')
        ct_cloudtrail_stackset = cloudFormation_client.describe_stack_set(StackSetName=sysdig_ct_cloudtrail_stackset)
        logger.info('AWS CT CloudTrail Baseline StackSet found: {}'.format(sysdig_ct_cloudtrail_stackset))
        
        # Add KMS key policy
        ct_cloudtrail_stackset_kms = next((item for item in ct_cloudtrail_stackset['StackSet']['Parameters'] if item['ParameterKey'] == 'KMSKeyArn'), False)
        if ct_cloudtrail_stackset_kms:
            ct_cloudtrail_kms_key = ct_cloudtrail_stackset_kms['ParameterValue']
            logger.info('AWS CT CloudTrail KMS Key found: {}'.format(ct_cloudtrail_kms_key))
            return ct_cloudtrail_kms_key
        else:
            logger.info('AWS CT CloudTrail KMS Key not found')
            return False
    except Exception as e:
        logger.error("CloudTrail KMS Key Handler error: {}".format(e))
        return False

# This module perform the following:
# 1. Check if AWS CT CloudTrail StackSet exist
# 2. Ifexist, find the log archive and audit account id
def ct_core_account_handler(regionName):
    try:
        # Check StackSet param
        cloudFormation_client = session.client('cloudformation')
        ct_cloudtrail_stackset = cloudFormation_client.describe_stack_set(StackSetName=sysdig_ct_cloudtrail_stackset)
        logger.info('AWS CT CloudTrail Baseline StackSet found: {}'.format(sysdig_ct_cloudtrail_stackset))
        
        # Find audit and log archive account
        auditAccount = next((item['ParameterValue'] for item in ct_cloudtrail_stackset['StackSet']['Parameters'] if item['ParameterKey'] == 'SecurityAccountId'), False)
        logger.debug("Audit Account: {}".format(auditAccount))
        
        logArchiveAccount = next((item['ParameterValue'].split('-')[3] for item in ct_cloudtrail_stackset['StackSet']['Parameters'] if item['ParameterKey'] == 'AuditBucketName'), False)
        logger.debug("Log Archive Account: {}".format(logArchiveAccount))
        
        # Find CloudTrail SNS topic name
        cloudTrailSNSTopic = next((item['ParameterValue'] for item in ct_cloudtrail_stackset['StackSet']['Parameters'] if item['ParameterKey'] == 'AllConfigTopicName'), False)
        cloudTrailSNSTopic = 'arn:aws:sns:' + regionName + ':' + auditAccount + ':' + cloudTrailSNSTopic
        
        logger.info("Audit & Log Archive account found: {} {}".format(auditAccount, logArchiveAccount))
        logger.info("CloudTrail SNS topic name : {}".format(cloudTrailSNSTopic))
        
        return auditAccount, logArchiveAccount, cloudTrailSNSTopic
    except Exception as e:
        logger.error("CT Core Account handler error: {}".format(e))
        return False, False, False

def lambda_handler(event, context):
    logger.info(json.dumps(event))
    try:
        #First launch via Cfn custom resource
        if 'RequestType' in event: helper(event, context)
        #Call back from Log archive stackset instance
        elif 'Records' in event: 
            messages = event['Records']
            for message in messages:
                payload = json.loads(message['Sns']['Message'])
                logger.info("Callback initiated from {}".format(payload['StackId']))
                logger.info(json.dumps(payload))
                callback_helper(payload, context)
                logger.info("Callback finished")
    except Exception as e:
        helper.init_failure(e)
