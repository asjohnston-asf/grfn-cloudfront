from json import loads
from http.cookies import SimpleCookie
from urllib.parse import urlunsplit, quote_plus

import jwt
from boto3 import client

SECRETS_MANAGER = client('secretsmanager', region_name='us-east-1')
CONFIG = None


def load_config(secret_name):
    secret = SECRETS_MANAGER.get_secret_value(SecretId=secret_name)
    global CONFIG
    CONFIG = loads(secret['SecretString'])


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
    invoked_url = urlunsplit(['https', CONFIG['domainName'], request['uri'], '', ''])
    redirect_url = CONFIG['authUrl'] + '&state=' + quote_plus(invoked_url)
    if not browser_user_agent(request['headers']):
        redirect_url += '&app_type=401'
    return redirect_response(redirect_url)


def lambda_handler(event, context):
    request = event['Records'][0]['cf']['request']
    headers = request['headers']

    if not CONFIG:
        secret_name = context.function_name.split('.')[-1]
        load_config(secret_name)

    if not headers.get('cookie'):
        return redirect_to_login(request)

    cookie = SimpleCookie(headers['cookie'][0]['value'])
    if not cookie.get(CONFIG['cookieName']):
        return redirect_to_login(request)

    token = cookie[CONFIG['cookieName']].value
    try:
        jwt.decode(token, CONFIG['publicKey'])
    except (jwt.DecodeError, jwt.ExpiredSignatureError):
        return redirect_to_login(request)

    return request
