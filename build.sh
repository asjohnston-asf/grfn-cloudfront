pip3 install -t src/ -r requirements.txt
find . -name "__pycache__" | xargs rm -R
find . -name "*dist-info" | xargs rm -R
sed "s/REPLACE/$(date +%s)/" cloudformation.yaml > cf.yaml
aws cloudformation package --template-file cf.yaml --s3-bucket asjohnston-dev --s3-prefix cloudformation/ --output-template-file cf.yaml
aws cloudformation deploy --template-file cf.yaml --stack-name asjohnston-cloudfront-dev --capabilities CAPABILITY_NAMED_IAM
