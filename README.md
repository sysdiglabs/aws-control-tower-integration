# Sysdig AWS Control Tower Integration

This repo provide example of integration for Sysdig CloudConnector (Real-Time Threat Investigation based on CloudTrail) inside AWS Control Tower environment

## Getting Started 

Run the following command on your AWS Control Tower management account (requires Admin privilege)

```
aws cloudformation create-stack --stack-name Sysdig-CT --template-url https://wellsiau-quickstart.s3.amazonaws.com/sysdig/templates/sysdig_ct_onboarding.yaml --parameters file://params.json --capabilities CAPABILITY_NAMED_IAM
```

Example of the `params.json`:

```
[
  {
    "ParameterKey": "SysdigSecureEndpoint",
    "ParameterValue": "https://us2.app.sysdig.com"
  }, 
  {
    "ParameterKey": "SysdigSecureAPIToken",
    "ParameterValue": "REDACTED - CHANGE WITH YOUR SYSDIG TOKEN"
  },
  {
    "ParameterKey": "StackSetName",
    "ParameterValue": "Sysdig-Secure-CT"
  },
  {
    "ParameterKey": "StackSetUrl",
    "ParameterValue": "https://wellsiau-quickstart.s3.amazonaws.com/sysdig/templates/sysdig_ct_stackset.yaml"
  },
  {
    "ParameterKey": "QSS3BucketName",
    "ParameterValue": "wellsiau-quickstart"
  },
  {
    "ParameterKey": "QSS3KeyPrefix",
    "ParameterValue": "sysdig/"
  },
  {
    "ParameterKey": "AuditAccount",
    "ParameterValue": "CHANGE WITH YOUR AWS CT AUDIT ACCOUNT"
  },
  {
    "ParameterKey": "LogArchiveAccount",
    "ParameterValue": "CHANGE WITH YOUR AWS CT LOG ARCHIVE ACCOUNT"
  }
]
```