import jwt
from requests_oauthlib import OAuth2Session
from json import loads
from urllib.parse import parse_qs
from datetime import datetime, timedelta
from http.cookies import SimpleCookie
from ipaddress import ip_network, ip_address
import boto3
import requests

secrets_manager = boto3.client('secretsmanager', region_name='us-east-1')
s3 = boto3.client('s3')

config = None
urs = None
aws_ip_blocks = None


def setup(secret_name):
    print('setting up')

    global config
    secret = secrets_manager.get_secret_value(SecretId=secret_name)
    config = loads(secret['SecretString'])

    global urs
    redirect_uri = 'https://' + config['cloudfrontDomain'] + '/oauth'
    urs = OAuth2Session(config['ursClientId'], redirect_uri=redirect_uri)

    global aws_ip_blocks
    response = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
    response.raise_for_status()
    ip_ranges = response.json()
    aws_ip_blocks = [ip_network(item['ip_prefix']) for item in ip_ranges['prefixes'] if item['service'] == 'AMAZON']
    aws_ip_blocks += [ip_network(item['ipv6_prefix']) for item in ip_ranges['ipv6_prefixes'] if item['service'] == 'AMAZON']


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


def request_from_aws(ip):
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
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        print('bad session-token')
        return redirect_to_login(request)
    print(payload['user_id'])
    print(request['uri'])
    if request_from_aws(request['clientIp']):
        print('aws request')
        return redirect_to_s3(request['uri'][1:], payload['user_id'])
    return request
