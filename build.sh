pip3 install -t viewer-request/src/ -r viewer-request/requirements.txt
pip3 install -t log-parse/src/ -r log-parse/requirements.txt
find . -name "__pycache__" | xargs rm -R
find . -name "*dist-info" | xargs rm -R
sed "s/REPLACE/$(date +%s)/" cloudformation.yaml > cf.yaml
date +%s > viewer-request/src/dummy-file
aws cloudformation package --template-file cf.yaml --s3-bucket asjohnston-dev --s3-prefix cloudformation --output-template-file cf.yaml
aws cloudformation deploy --template-file cf.yaml --stack-name asjohnston-cf-dev --capabilities CAPABILITY_NAMED_IAM
