import jwt
from requests_oauthlib import OAuth2Session
from json import loads
from urllib.parse import parse_qs
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
import boto3
import requests

secrets_manager = boto3.client('secretsmanager', region_name='us-east-1')
secret = secrets_manager.get_secret_value(SecretId='grfn-cloudfront-secret')
config = loads(secret['SecretString'])

authorization_base_url = config['ursHostname'] + 'oauth/authorize'
redirect_uri = 'https://' + config['cloudfrontDomain'] + '/oauth'
urs = OAuth2Session(config['ursClientId'], redirect_uri=redirect_uri)


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
    authorization_url, state = urs.authorization_url(authorization_base_url, state=request['uri'])
    if 'user-agent' not in request['headers'] or not request['headers']['user-agent'][0]['value'].startswith('Mozilla'):
        authorization_url += '&app_type=401'
    response = redirect_response(authorization_url)
    return response


def get_session_token(request):
    parms = parse_qs(request['querystring'])
    token_uri = config['ursHostname'] + 'oauth/token'
    token = urs.fetch_token(token_uri, code=parms['code'][0], client_secret=config['ursClientPassword'])
    user_profile_uri = config['ursHostname'] + token['endpoint'][1:]
    response = requests.get(user_profile_uri, headers={'Authorization': token['token_type'] + ' ' + token['access_token']})
    response.raise_for_status()
    user = response.json()
    expiration_time = datetime.utcnow() + timedelta(seconds=60)
    payload = {
        'user_id': user['uid'],
        'exp': expiration_time.strftime('%s'),
    }
    session_token = jwt.encode(payload, config['secretKey'], 'HS256')
    redirect_url = 'https://' + config['cloudfrontDomain'] + parms['state'][0]
    response = redirect_response(redirect_url)
    response['headers']['set-cookie'] = [{
        'key': 'Set-Cookie',
        'value': 'session-token=' + session_token.decode('utf-8'),
    }]
    return response


def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']
    headers = request['headers']

    if is_oauth_request(request):
        print('oauth request')
        return get_session_token(request)
    if 'cookie' not in headers:
        print('no cookie')
        return redirect_to_login(request)
    cookie = SimpleCookie(headers['cookie'][0]['value'])
    if 'session-token' not in cookie:
        print('no session-token in cookie')
        return redirect_to_login(request)
    token = cookie['session-token'].value
    try:
        payload = jwt.decode(token, config['secretKey'], algorithms=['HS256'])
        print(payload['user_id'])
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        print('bad session-token')
        return redirect_to_login(request)
    print(request['uri'])
    return request
