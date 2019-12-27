import json
from datetime import datetime, timedelta
from os import getenv
from boto3 import client


CLOUDWATCH = client('cloudwatch')
CLOUDFRONT = client('cloudfront')
CONFIG = json.loads(getenv('CONFIG'))


def get_cloudfront_charges():
    start_time = datetime.utcnow() - timedelta(seconds=CONFIG['Period'])
    end_time = datetime.utcnow()

    queries = [{
        'Id': 'result',
        'MetricStat': {
            'Period': CONFIG['Period'],
            'Stat': 'Maximum',
            'Metric': {
                'Namespace': 'AWS/Billing',
                'MetricName': 'EstimatedCharges',
                'Dimensions': [
                    {
                        'Name': 'Currency',
                        'Value': 'USD',
                    },
                    {
                        'Name': 'ServiceName',
                        'Value': 'AmazonCloudFront',
                    },
                ],
            },
        },
    }]

    response = CLOUDWATCH.get_metric_data(MetricDataQueries=queries, StartTime=start_time, EndTime=end_time)
    charges = max(response['MetricDataResults'][0]['Values'])
    return(charges)


def disable_distribution(distribution_id):
    response = CLOUDFRONT.get_distribution_config(Id=distribution_id)
    distribution_config = response['DistributionConfig']
    if distribution_config['Enabled']:
        print(f'Disabling distribution {distribution_id}')
        distribution_config['Enabled'] = False
        response = CLOUDFRONT.update_distribution(Id=distribution_id, DistributionConfig=distribution_config, IfMatch=response['ETag'])


def lambda_handler(event, conext):
    charges = get_cloudfront_charges()
    print(f'Current Charges: ${charges}')
    if charges > CONFIG['Threshhold']:
        print(f'Current charges (${charges}) are greater than threshhold (${CONFIG["Threshhold"]})')
        disable_distribution(CONFIG['DistributionId'])
