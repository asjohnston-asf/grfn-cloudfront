import jwt
from requests_oauthlib import OAuth2Session
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


def redirect_to_login(request):
    authorization_base_url = config['ursHostname'] + 'oauth/authorize'
    state = request['uri']
    redirect_uri = 'https://' + config['cloudfrontDomain'] + '/oauth'
    urs = OAuth2Session(config['ursClientId'], redirect_uri=redirect_uri, state=state)
    authorization_url, state = urs.authorization_url(authorization_base_url)
    response = redirect_response(authorization_url)
    return response


def lambda_handler(event, context):
    print(event)
    print(config)
    request = event['Records'][0]['cf']['request']
    headers = request['headers']

    if is_oauth_request(request):
        return redirect_response('https://www.google.com')
    if 'session-token' not in headers:
        return redirect_to_login(request)
    else:
        token = headers['session-token'][0]['value']
        try:
            jwt.decode(token, config['secretKey'], algorithms=['HS256'])
        except (jwt.DecodeError, jwt.ExpiredSignatureError):
            return redirect_to_login(request)
    return request
