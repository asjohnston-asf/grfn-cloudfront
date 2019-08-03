import jwt
#from requests_oauthlib import OAuth2Session
from json import loads
import boto3

secrets_manager = boto3.client('secretsmanager', region_name='us-east-1')
secret = secrets_manager.get_secret_value(SecretId='grfn-cloudfront-secret')
config = loads(secret['SecretString'])


def is_oauth_request(request):
    return request['uri'] == '/oauth'


def redirect_response(url):
    return {
        'status': '302',
        'statusDescription': 'Found',
        'headers': {
            'location': [{
                'key': 'Location',
                'value': url
            }],
        },
    }


def lambda_handler(event, context):
    print(event)
    print(config)
    request = event['Records'][0]['cf']['request']
    headers = request['headers']

    if is_oauth_request(request):
        return redirect_response('https://www.google.com')
    if 'session-token' not in headers:
        return redirect_response('https://www.xkcd.com')
    else:
        token = headers['session-token'][0]['value']
        try:
            jwt.decode(token, config['secretKey'], algorithms=['HS256'])
        except (jwt.DecodeError, jwt.ExpiredSignatureError):
            return redirect_response('https://www.wikipedia.org')
    return request
