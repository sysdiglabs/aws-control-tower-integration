#S3_BUCKET?="manu-test-cf"
#S3_PREFIX?="test"
# We need the REGION or the TemplateURLs might be created for a different region, resulting in a deployment error
#S3_REGION="us-east-1"
#SECURE_API_TOKEN=""

.PHONY: packaged-template.yaml

# validate:
#	aws cloudformation validate-template --template-body file://./sysdig_ct_onboarding.yaml

lint:
	cfn-lint *.yaml

#packaged-template.yaml:
#	aws s3 rm s3://$(S3_BUCKET)/$(S3_PREFIX) --recursive
#	aws cloudformation package \
#		--region $(S3_REGION) \
#		--template-file sysdig_ct_onboarding.yaml \
#		--s3-bucket $(S3_BUCKET) \
#		--s3-prefix $(S3_PREFIX) \
#		--output-template-file packaged-template.yaml
#		--force-upload \

#test: packaged-template.yaml
#	aws cloudformation deploy \
#		--stack-name "ControlTower test" \
#		--template-file packaged-template.yaml \
#		--capabilities "CAPABILITY_NAMED_IAM" "CAPABILITY_AUTO_EXPAND" \
#		--parameter-overrides \
#			"SysdigSecureAPIToken=$(SECURE_API_TOKEN)"

#ci: packaged-template.yaml
#	aws s3 cp ./packaged-template.yaml s3://$(S3_BUCKET)/$(S3_PREFIX)/entry-point.yaml
ci:
	echo "CI step"

#clean:
#	aws cloudformation delete-stack --stack-name "Stack Name"
