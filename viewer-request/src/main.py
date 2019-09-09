from json import loads
from urllib.parse import parse_qs
from datetime import datetime, timedelta
from http.cookies import SimpleCookie

import jwt
from boto3 import client
from requests_oauthlib import OAuth2Session
from oauthlib.oauth2 import InvalidGrantError

SECRETS_MANAGER = client('secretsmanager', region_name='us-east-1')

CONFIG = None
URS = None
AWS_IP_BLOCKS = None


def setup(secret_name, cloudfront_domain_name):
    global CONFIG
    CONFIG = get_config(secret_name)

    global URS
    redirect_uri = 'https://' + cloudfront_domain_name + '/oauth'
    URS = OAuth2Session(CONFIG['ursClientId'], redirect_uri=redirect_uri)


def get_config(secret_name):
    secret = SECRETS_MANAGER.get_secret_value(SecretId=secret_name)
    config = loads(secret['SecretString'])
    return config


def client_error_response():
    return {
        'status': '400',
        'statusDescription': 'Bad Request',
    }


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


def browser_user_agent(headers):
    if not headers.get('user-agent'):
        return False
    for header in headers['user-agent']:
        if not header['value'].startswith('Mozilla'):
            return False
    return True


def redirect_to_login(request):
    authorization_base_url = CONFIG['ursHostname'] + '/oauth/authorize'
    authorization_url, state = URS.authorization_url(authorization_base_url, state=request['uri'])
    if not browser_user_agent(request['headers']):
        authorization_url += '&app_type=401'
    return redirect_response(authorization_url)


def set_cookie_header(token):
    cookie = SimpleCookie()
    cookie['session-token'] = token
    cookie['session-token']['expires'] = CONFIG['sessionDurationInSeconds']
    header = [{
        'key': 'Set-Cookie',
        'value': cookie.output(header='')
    }]
    return header


def get_session_token(request):
    parms = parse_qs(request['querystring'])
    if not parms.get('code'):
        return client_error_response()

    token_uri = CONFIG['ursHostname'] + '/oauth/token'
    try:
        urs_token = URS.fetch_token(token_uri, code=parms['code'][0], client_secret=CONFIG['ursClientPassword'])
    except InvalidGrantError:
        return client_error_response()

    user_id = urs_token['endpoint'].split('/')[-1]
    expiration_time = datetime.utcnow() + timedelta(seconds=CONFIG['sessionDurationInSeconds'])
    payload = {
        'user_id': user_id,
        'exp': expiration_time.strftime('%s'),
    }
    session_token = jwt.encode(payload, CONFIG['secretKey'], 'HS256')

    redirect_url = parms.get('state', ['/'])[0]
    response = redirect_response(redirect_url)
    response['headers']['set-cookie'] = set_cookie_header(session_token.decode('utf-8'))
    return response


def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']
    headers = request['headers']

    if not CONFIG:
        secret_name = context.function_name.split('.')[-1]
        cloudfront_domain_name = event['Records'][0]['cf']['config']['distributionDomainName']
        setup(secret_name, cloudfront_domain_name)

    if request['uri'] == '/oauth':
        return get_session_token(request)

    if not headers.get('cookie'):
        return redirect_to_login(request)

    cookie = SimpleCookie(headers['cookie'][0]['value'])
    if not cookie.get('session-token'):
        return redirect_to_login(request)

    token = cookie['session-token'].value
    try:
        jwt.decode(token, CONFIG['secretKey'], algorithms=['HS256'])
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        return redirect_to_login(request)

    return request
