from json import loads
from urllib.parse import parse_qs
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from ipaddress import ip_network, ip_address

import requests
import jwt
import boto3
from requests_oauthlib import OAuth2Session

secrets_manager = boto3.client('secretsmanager', region_name='us-east-1')
s3 = boto3.client('s3')

config = None
urs = None
aws_ip_blocks = None


def setup(secret_name):
    global config
    config = get_config(secret_name)

    global urs
    redirect_uri = 'https://' + config['cloudfrontDomain'] + '/oauth'
    urs = OAuth2Session(config['ursClientId'], redirect_uri=redirect_uri)

    global aws_ip_blocks
    aws_ip_blocks = get_aws_ip_blocks()


def get_config(secret_name):
    secret = secrets_manager.get_secret_value(SecretId=secret_name)
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


def redirect_to_login(request):
    authorization_base_url = config['ursHostname'] + '/oauth/authorize'
    authorization_url, state = urs.authorization_url(authorization_base_url, state=request['uri'])
    if 'user-agent' not in request['headers'] or not request['headers']['user-agent'][0]['value'].startswith('Mozilla'):
        authorization_url += '&app_type=401'
    response = redirect_response(authorization_url)
    return response


def set_cookie_header(token):
    cookie = SimpleCookie()
    cookie['session-token'] = token
    cookie['session-token']['expires'] = config['sessionDurationInSeconds']
    set_cookie_header = [{
        'key': 'Set-Cookie',
        'value': cookie.output(header='')
    }]
    return set_cookie_header


def get_session_token(request):
    parms = parse_qs(request['querystring'])
    token_uri = config['ursHostname'] + '/oauth/token'
    token = urs.fetch_token(token_uri, code=parms['code'][0], client_secret=config['ursClientPassword'])
    user_profile_uri = config['ursHostname'] + token['endpoint']
    response = requests.get(user_profile_uri, headers={'Authorization': token['token_type'] + ' ' + token['access_token']})
    response.raise_for_status()
    user = response.json()
    expiration_time = datetime.utcnow() + timedelta(seconds=config['sessionDurationInSeconds'])
    payload = {
        'user_id': user['uid'],
        'exp': expiration_time.strftime('%s'),
    }
    session_token = jwt.encode(payload, config['secretKey'], 'HS256')
    redirect_url = 'https://' + config['cloudfrontDomain'] + parms['state'][0]
    response = redirect_response(redirect_url)
    response['headers']['set-cookie'] = set_cookie_header(session_token.decode('utf-8'))
    return response


def is_aws_address(ip):
    addr = ip_address(ip)
    for block in aws_ip_blocks:
        if addr in block:
            return True
    return False


def redirect_to_s3(key, user_id):
    signed_url = s3.generate_presigned_url(
        ClientMethod='get_object',
        Params={
            'Bucket': config['bucket'],
            'Key': key,
        },
        ExpiresIn=60,
    )
    signed_url += '&userid=' + user_id
    return redirect_response(signed_url)


def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']
    headers = request['headers']

    if not config:
        setup(context.function_name.split('.')[-1])

    if request['uri'] == '/oauth':
        return get_session_token(request)

    if 'cookie' not in headers:
        return redirect_to_login(request)

    cookie = SimpleCookie(headers['cookie'][0]['value'])
    if 'session-token' not in cookie:
        return redirect_to_login(request)

    token = cookie['session-token'].value
    try:
        payload = jwt.decode(token, config['secretKey'], algorithms=['HS256'])
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        return redirect_to_login(request)

    if is_aws_address(request['clientIp']):
        return redirect_to_s3(request['uri'].lstrip('/'), payload['user_id'])

    return request
