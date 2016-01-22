'use strict';

var PromiseA = require('bluebird');
var scoper = require('app-scoped-ids');

module.exports.create = function (config, TokenStore, ClientsCtrl, Logins, Signer) {
  var authutils = require('secret-utils');

  /**
   * ResourceOwnerPasswordStrategy
   *
   * This strategy is used to authenticate registered OAuth clients WITH users'
   * credentials. It is employed to protect the `token` endpoint, which consumers
   * use to obtain access tokens on behalf of the users supplying credentials.
   * This is primary for use with privileged applications in insecure environments
   * (such as an official mobile app)
   */
  function getClientAndUser(params/*, opts*/) {
    // TODO needs a way to specify which tos is agreeable to the client,
    // probably .well-known/oauth3/toses or something like that
    // TODO origin / referer (currently passing clientUri)
    return ClientsCtrl.loginOrCreate({ /*tosUrl: ''*/ }, params.clientId, params.clientSecret, params).then(function (apiKey) {
      // NOTE: if the service allows apps to create their own users,
      // the app id and/or tenant id would help distinguish between them
      // (and the type could change to 'app-scoped')

      return Logins.login({
        node: params.username
      , type: params.usernameType || null
      , secret: params.password
      , totp: params.totp || ''
      // , tenantId:  params.tenantId
      }, params).then(function (login) {
        if (!login) {
          throw new Error("[SANITY FAIL] succeeded without user");
        }

        return { login: login, apiKey: apiKey };
      });
    }, function (err) {
      // authentication failed
      if (err.code === 'ETIMEDOUT') {
        // err.connect // was TCP issues
        throw err;
      }

      if (/Incorrect/i.test(err && err.message)) {
        //return { apikey: null, login: null };
        return PromiseA.reject(err);
      } else {
        console.error('[ERROR] getClientAndUser [resource owner password] - Unknown');
        console.warn(err.stack || err);

        return PromiseA.reject(err);
      }
    }).catch(function (err) {
      console.error("[ERROR] getClientAndUser");
      console.warn(err.stack || err);

      throw err;
    });
  }

  /**
   * GrantTypePasswordExchange
   *
   * Given an authentic API Client and User, grant a token with the requested scope
   */
  function exchangePasswordToken(auth, params) {
    var err;
    var apiKey = auth.apiKey;
    var oauthClient = apiKey.oauthClient;
    var login = auth.login;
    var issuedAt;
    var tokenMeta;
    //var refreshToken; // = undefined
    var expiresAt;
    var expiresIn;

    // TODO
    // the app should not be able to request scope greater than
    // what has been granted through the noraml oauth flow
    // (or specially granted by an admin)

    // TODO Trusted Clients
    // Check params.origin, params.referer (browser) or params.cname, params.ip (server)
    if (!apiKey.test && !oauthClient.root && 'groot' !== oauthClient.accountId) {
      apiKey.key = '[scrubbed]';
      if (apiKey.secret) {
        apiKey.secret = '[scrubbed]';
      }
      if (oauthClient.secret) {
        oauthClient.secret = '[scrubbed]';
      }

      console.warn('apiKey', apiKey);
      console.warn('oauthClient', oauthClient);
      err = new Error("trusted client checking not yet implemented (only allowed in test apps for now)");
      err.code = "E_NOT_IMPLEMENTED";
      return PromiseA.reject(err);
    }

    // TODO include MFA
    issuedAt = Math.floor(Date.now() / 1000);
    expiresIn = 30 * 60; // 30 minutes
    //expiresIn = 30 * 24 * 60 * 60; // 30 days
    //expiresAt = new Date(Date.now() + (expiresIn * 1000)).toISOString();
    expiresAt = new Date(Date.now() + (expiresIn * 1000)).valueOf();
    // TODO [JWT] squish all of this into a JWT
    tokenMeta = {
      // standard
      iss: undefined // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.1
    , sub: undefined // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.2
    , aud: undefined // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.3
    , exp: Math.floor(expiresAt / 1000)
    , iat: issuedAt
    , nbf: undefined // not before... weird
    , jti: undefined // just use hash of the token instead?
      // extended
    , k:   apiKey.id || apiKey.key                                                // apiKeyId
    , app: oauthClient.id                                                         // oauthClientId
    , usr: login.id || login.hashId                                               // loginId
    , acc: login.primaryAccountId && { id: login.primaryAccountId }               // selectedAccountId
    , acs: (login.accounts||[]).map(function (a) { return a && { id: a.id }; })
    , idx: scoper.scope(login.id || login.hashId, oauthClient.secret)             // loginId
    , acx: login.primaryAccountId && {                                            // selectedAccountId
              id: scoper.scope(login.primaryAccountId, oauthClient.secret)
            }
    , aax: (login.accounts||[]).map(function (a) {
              return a && { appScopedId: scoper.scope(a.id, oauthClient.secret) };
            })
    , scp: params.scope.join(' ')                                                 // acceptedScopeString
    , as: 'login'
    , srv: (apiKey.server && oauthClient.server) || !(apiKey.insecure || oauthClient.insecure) // server / insecure
    , grt: 'password'                                                             // grantType

    // for testing, not for actionable normal use
    , test: apiKey.test || oauthClient.test || undefined

    //, requestedScopeString: params.scope.join(' ')
    };

    return Signer.sign(tokenMeta).then(function (accessToken) {
      // storing token to audit session
      var id = authutils.hashsum('sha256', accessToken);
      return TokenStore.create({
        id: id

      , userAgent: params.userAgent
      , ip: params.ip
      , origin: params.origin
      , referer: params.referer
      , scope: params.scope.join(' ')
      , secure: params.secure
      , test: tokenMeta.test

      , expiresAt: expiresAt
      , issuedAt: expiresAt

      , accessToken: accessToken
      }).then(function() {
        // this in turn causes the sha256 id to change
        tokenMeta.refresh = true;
        tokenMeta.exp = undefined;
        return Signer.sign(tokenMeta).then(function (refreshToken) {
          var id = authutils.hashsum('sha256', refreshToken);
          return TokenStore.create({
            id: id

          , userAgent: params.userAgent
          , ip: params.ip
          , origin: params.origin
          , referer: params.referer
          , scope: params.scope.join(' ')
          , secure: params.secure
          , test: tokenMeta.test

          , expiresAt: expiresAt
          , issuedAt: expiresAt

          , refreshToken: refreshToken
          }).then(function () {
            return {
              accessToken: accessToken
            , refreshToken: refreshToken
            , tokenType: 'bearer'
            , expiresIn: expiresIn
            , scope: tokenMeta.scp
            };
          });
        });
      });
    });
  }

  // grant_type=['client_credentials', 'password', 'delegated', 'code', 'implicit']
  // response_type=['authorization_code']
  function parseResourceOwnerPassword(req/*, opts*/) {
    var params = req.body;

    if (!params) {
      return PromiseA.reject(new Error("grant_type 'password' is missing parameters object"));
    }
    else if (!(params.client_id || params.clientId)) {
      return PromiseA.reject(new Error("grant_type 'password' is missing 'client_id' parameter"));
    }
    else if (!params.username) {
      return PromiseA.reject(new Error("grant_type 'password' is missing 'username' parameter"));
    }
    else if (!params.password) {
      return PromiseA.reject(new Error("grant_type 'password' is missing 'password' parameter (misnomer: password refers to the secret, passphrase, or other authentication token)"));
    }

    return PromiseA.resolve({
      clientId: params.client_id || params.clientId
    , clientSecret: params.client_secret || params.clientSecret
    , clientAgreeTos: params.client_agree_tos || params.clientAgreeTos
      || params.agree_tos || params.agreeTos
    , clientSignature: params.client_signature || params.client_tos_signature
    , clientUri: params.client_uri

    , username: params.username // TODO separator for type?
    , usernameType: params.username_type || undefined
    , password: params.password
    //, userAgreeTos: params.user_agree_tos || params.agree_tos
    //, userSignature: params.user_signature || params.signature

      // since OAuth3 is federated tenants shouldn't be necessary... right?
    , tenantId: params.tenant_id || params.tenantId
    , scope: (params.scope||'').split(/\s+/g).filter(function (str) { return str; })

    , mfa: params.mfa // TODO an array of arbitrary MFA
    , totp: params.totp // for Authenticator

    , origin: req.headers.origin
    , referer: req.headers.referer
    , ip: req.ip || req.socket.remoteAddress
    , userAgent: req.headers['user-agent']

    , secure: req.secure || 'https' === req.protocol || req.socket.encrypted
    });
    // TODO? sms MFA
    // TODO? qr-based MFA
  }

  return {
    parseResourceOwnerPassword: parseResourceOwnerPassword
  , exchangePasswordToken: exchangePasswordToken
  , getClientAndUser: getClientAndUser
  };
};
