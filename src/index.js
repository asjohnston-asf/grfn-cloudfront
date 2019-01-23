'use strict';


const EarthdataLoginClient = require('./lib/EarthdataLogin');
const jwt = require('jsonwebtoken');
const urljoin = require('url-join');
const querystring = require('querystring');
const cookieLib = require('cookie');
const SecretsManager = require('aws-sdk/clients/secretsmanager');
const secretsManager = new SecretsManager({region: 'us-east-1'});


async function getConfig() {
  const request = secretsManager.getSecretValue({SecretId: 'grfn-cloudfront-secret'});
  const result = await request.promise();
  return JSON.parse(result.SecretString);
}

const configPromise = getConfig();


function redirectResponse(location) {
  return {
    status: '307',
    statusDescription: 'Temporary Redirect',
    headers: {
      location: [{
        key: 'Location',
        value: location
      }]
    }
  };
}


function parseCookies(headers) {
  let parsedCookies = {};
  if (headers.cookie) {
    for (let i = 0; i < headers.cookie.length; i++) {
      headers.cookie[i].value.split(';').forEach((cookie) => {
        if (cookie) {
          const parts = cookie.split('=');
          parsedCookies[parts[0].trim()] = parts[1].trim();
        }
      });
    }
  }
  return parsedCookies;
}


function isRedirectRequest(request) {
  return request.uri === '/redirect';
}


function getAccessTokenFromRequest(request) {
  const parsedCookies = parseCookies(request.headers);
  if (parsedCookies && parsedCookies['accessToken']) {
    return parsedCookies['accessToken'];
  }
  return null;
}


function getExpDate() {
  return new Date(Date.now() + 60000);
}


async function handleRedirectRequest(params = {}) {
  const {
    authClient,
    distributionUrl,
    secretKey,
    request
  } = params;

  const queryStringParameters = querystring.parse(request.querystring);
  const accessTokenResponse = await authClient.getAccessToken(queryStringParameters.code);

  const expDate = getExpDate();
  const payload = {
    username: accessTokenResponse.username,
    exp: Math.floor(expDate.getTime()/1000)
  };
  const accessToken = jwt.sign(payload, secretKey);
  const cookie = cookieLib.serialize('accessToken', accessToken, {expires: expDate});

  return {
    status: '307',
    statusDescription: 'Temporary Redirect',
    headers: {
      'location': [{
        key: 'Location',
        value: urljoin(distributionUrl, queryStringParameters.state)
      }],
      'set-cookie': [{
        key: 'Set-Cookie',
        value: cookie
      }]
    }
  };
}


function getUserAgent(request) {
  let userAgent = null;
  if (request.headers && 'user-agent' in request.headers) {
    userAgent = request.headers['user-agent'][0].value;
  }
  return userAgent;
}


async function handleFileRequest(params = {}) {
  const {
    authClient,
    secretKey,
    request,
  } = params;

  const userAgent = getUserAgent(request);
  const redirectUrl = authClient.getAuthorizationUrl(request.uri, userAgent);
  const redirectToGetAuthorizationCode = redirectResponse(redirectUrl);
  const accessToken = getAccessTokenFromRequest(request);

  if (!accessToken) {
    console.log('no access token');
    return redirectToGetAuthorizationCode;
  }

  try {
    const payload = jwt.verify(accessToken, secretKey);
    console.log(payload['username']);
  } catch(err) {
    console.log('bad token');
    return redirectToGetAuthorizationCode;
  }

  return request;
}


async function handleRequest(params = {}) {
  const {
    authClient,
    distributionUrl,
    secretKey,
    request
  } = params;

  if (isRedirectRequest(request)) {
    return await handleRedirectRequest({
      authClient,
      distributionUrl,
      secretKey,
      request
    });
  }

  return await handleFileRequest({
    authClient,
    secretKey,
    request
  });
}


exports.handler = async function(event, context) {
  const request = event.Records[0].cf.request;
  const config = await configPromise;

  const earthdataLoginClient = new EarthdataLoginClient({
    clientId: config.ursClientId,
    clientPassword: config.ursClientPassword,
    earthdataLoginUrl: config.ursHostname,
    redirectUri: `https://${config.cloudfrontDomain}/redirect`
  });

  const response = await handleRequest({
    authClient: earthdataLoginClient,
    distributionUrl: `https://${config.cloudfrontDomain}/`,
    secretKey: config.secretKey,
    request: request
  });

  return response;
};
