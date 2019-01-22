'use strict';


const EarthdataLoginClient = require('./lib/EarthdataLogin');
const jwt = require('jsonwebtoken');
const urljoin = require('url-join');
const querystring = require('querystring');
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


async function handleRedirectRequest(params = {}) {
  const {
    authClient,
    distributionUrl,
    privateKey,
    request
  } = params;

  const queryStringParameters = querystring.parse(request.querystring);
  const accessTokenResponse = await authClient.getAccessToken(queryStringParameters.code);

  const payload = {
    username: accessTokenResponse.username
  };

  const options = {
    algorithm: 'RS256',
    expiresIn: 60
  };

  const accessToken = jwt.sign(payload, privateKey, options);

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
        value: `accessToken=${accessToken}`
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
    publicKey,
    request,
  } = params;

  const userAgent = getUserAgent(request);
  const redirectUrl = authClient.getAuthorizationUrl(request.uri, userAgent)
  const redirectToGetAuthorizationCode = redirectResponse(redirectUrl);
  const accessToken = getAccessTokenFromRequest(request);

  if (!accessToken) {
    console.log('no access token');
    return redirectToGetAuthorizationCode;
  }

  try {
    const payload = jwt.verify(accessToken, publicKey);
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
    publicKey,
    privateKey,
    request
  } = params;

  if (isRedirectRequest(request)) {
    return await handleRedirectRequest({
      authClient,
      distributionUrl,
      privateKey,
      request
    });
  }

  return await handleFileRequest({
    authClient,
    publicKey,
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
    publicKey: config.publicKey,
    privateKey: config.privateKey,
    request: request
  });

  return response;
};
