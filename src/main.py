from json import loads
from urllib.parse import parse_qs
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from ipaddress import ip_network, ip_address

import requests
import jwt
import boto3
from requests_oauthlib import OAuth2Session

SECRETS_MANAGER = boto3.client('secretsmanager', region_name='us-east-1')
S3 = boto3.client('s3')

CONFIG = None
URS = None
AWS_IP_BLOCKS = None


def setup(secret_name):
    global CONFIG
    CONFIG = get_config(secret_name)

    global URS
    redirect_uri = 'https://' + CONFIG['cloudfrontDomain'] + '/oauth'
    URS = OAuth2Session(CONFIG['ursClientId'], redirect_uri=redirect_uri)

    global AWS_IP_BLOCKS
    AWS_IP_BLOCKS = get_aws_ip_blocks()


def get_config(secret_name):
    secret = SECRETS_MANAGER.get_secret_value(SecretId=secret_name)
    config = loads(secret['SecretString'])
    return config


def get_aws_ip_blocks():
    response = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
    response.raise_for_status()
    ip_ranges = response.json()
    aws_ip_blocks = [ip_network(item['ip_prefix']) for item in ip_ranges['prefixes'] if item['service'] == 'AMAZON']
    aws_ip_blocks += [ip_network(item['ipv6_prefix']) for item in ip_ranges['ipv6_prefixes'] if item['service'] == 'AMAZON']
    return aws_ip_blocks


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
    token_uri = CONFIG['ursHostname'] + '/oauth/token'
    token = URS.fetch_token(token_uri, code=parms['code'][0], client_secret=CONFIG['ursClientPassword'])
    user_profile_uri = CONFIG['ursHostname'] + token['endpoint']
    response = requests.get(user_profile_uri, headers={'Authorization': token['token_type'] + ' ' + token['access_token']})
    response.raise_for_status()
    user = response.json()
    expiration_time = datetime.utcnow() + timedelta(seconds=CONFIG['sessionDurationInSeconds'])
    payload = {
        'user_id': user['uid'],
        'exp': expiration_time.strftime('%s'),
    }
    session_token = jwt.encode(payload, CONFIG['secretKey'], 'HS256')
    redirect_url = 'https://' + CONFIG['cloudfrontDomain'] + parms['state'][0]
    response = redirect_response(redirect_url)
    response['headers']['set-cookie'] = set_cookie_header(session_token.decode('utf-8'))
    return response


def is_aws_address(ip):
    addr = ip_address(ip)
    for block in AWS_IP_BLOCKS:
        if addr in block:
            return True
    return False


def redirect_to_s3(key, user_id):
    signed_url = S3.generate_presigned_url(
        ClientMethod='get_object',
        Params={
            'Bucket': CONFIG['bucket'],
            'Key': key,
        },
        ExpiresIn=CONFIG['sessionDurationInSeconds'],
    )
    signed_url += '&userid=' + user_id
    return redirect_response(signed_url)


def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']
    headers = request['headers']

    if not CONFIG:
        secret_name = context.function_name.split('.')[-1]
        setup(secret_name)

    if request['uri'] == '/oauth':
        return get_session_token(request)

    if not headers.get('cookie'):
        return redirect_to_login(request)

    cookie = SimpleCookie(headers['cookie'][0]['value'])
    if not cookie.get('session-token'):
        return redirect_to_login(request)

    token = cookie['session-token'].value
    try:
        payload = jwt.decode(token, CONFIG['secretKey'], algorithms=['HS256'])
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        return redirect_to_login(request)

    if is_aws_address(request['clientIp']):
        key = request['uri'].lstrip('/')
        return redirect_to_s3(key, payload['user_id'])

    return request
