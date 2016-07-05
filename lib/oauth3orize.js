'use strict';

var PromiseA = require('bluebird');
var scoper = require('app-scoped-ids');
var crypto = require('crypto');

//
// General Notes
//
// The Authorization Code is used as the template for the Refresh Token
// The Refresh Token is used as the template for the Access Token
//
// iss is the signer of the token, often also the audience (even if being signed on a different machine)
// aud is always the receiver of the token, often the issuer (even if being received first by another party)
// azp is always the user of the token, often the browser client or mobile app
// sub is always an account of the user
//
// jti is always unique
// iat is always the timestamp the token was created
// exp is when the token is no longer valid (although a client may continue to use an expired token in offline mode)
// auth_time (?) is when the user authorized via mfa (including 1fa)
//
// See Also
// ../packages/apis/org.oauth3.consumer/lib/token-signer.js
// ../packages/apis/org.oauth3.consumer/lib/config-store.js

module.exports.create = function (config, TokenStore, ClientsCtrl, LoginsCtrl, Signer, myRootClient) {
  var authutils = require('secret-utils');



  function mapSubIds(acx) {
    return acx.ppid || acx.appScopedId || acx.id || acx.sub;
  }
  function elementExists(e) {
    return e;
  }



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

      return LoginsCtrl.login({
        node: params.username
      , type: params.usernameType || null
      , secret: params.password
      , totp: params.totp || ''
      // , tenantId:  params.tenantId
      }, params).then(function (login) {
        if (!login) {
          throw new Error("[SANITY FAIL] succeeded without user");
        }

        return {
          apiKey: apiKey
        , oauthClient: apiKey.oauthClient
        , rootClient: params.rootClient

        , login: login
        };
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
   * ExchangeRefreshToken
   *
   * Exchange a refresh_token for a new access_token
   */
  function exchangeRefreshTokenHelperHelper(params, tokenMetaOriginal, axs, expiresIn) {
    // great name, right?
    var err;

    if (!tokenMetaOriginal.refresh) {
      err = new Error("not a refresh token");
      err.code = 'E_NOT_REFRESH';
      return PromiseA.reject(err);
    }

    var issuedAt = Math.floor(Date.now() / 1000);
    var expiresAt = new Date(Date.now() + (expiresIn * 1000)).valueOf();

    // Simply overwrite certain properties of the refreshToken for the new accessToken
    var tokenMeta = JSON.parse(JSON.stringify(tokenMetaOriginal));

    tokenMeta.refresh = undefined;
    tokenMeta.tokenType = 'bearer';

    tokenMeta.iat = issuedAt;
    tokenMeta.exp = Math.floor(expiresAt / 1000);

    // TODO check that these details make sense
    // NOTE: either userAgent or IP can be used as a device session identifier
    // if the IP or userAgent changes, perhaps revalidation should be required
    //tokenMeta.userAgent = params.userAgent;
    tokenMeta.ip = params.ip;
    //tokenMeta.origin = params.origin;
    //tokenMeta.referer = params.referer;
    //tokenMeta.isDeviceClient = !(params.origin || params.referer) || undefined;
    //tokenMeta.secure = params.secure;

    // TODO allow a lesser scope, but not a greater one
    //tokenMeta.scp = params.scope.join(' ');

    tokenMeta.axs = axs;
    tokenMeta.sub = tokenMeta.sub || axs.map(mapSubIds).filter(elementExists).join(',');

    return tokenMeta;
  }
  function exchangeRefreshTokenHelper(params, refreshToken, tokenMeta, axs) {
    var expiresIn = 30 * 60; // 30 minutes

    // TODO issue a new refreshToken if it is about to expire
    //if (tokenMeta.exp) {
    //}

    var tokenMetaCopy = exchangeRefreshTokenHelperHelper(params, tokenMeta, axs, expiresIn);

    return Signer.sign(tokenMetaCopy).then(function (accessToken) {
      return {
        accessToken: accessToken
      , refreshToken: refreshToken
      , tokenType: 'bearer'
      , expiresIn: expiresIn
      , expiresAt: tokenMetaCopy.expiresAt
      , scope: tokenMeta.scp
      };
    });
  }
  function exchangeRefreshToken(params/*, opts*/) {
    return Signer.verifyAsync(params.experienceId || params.origin, params.refreshToken).then(function (tokenMeta) {
      // TODO check accounts LoginsCtrl
      // TODO check params.clientId vs tokenMeta.k vs tokenMeta.app
      return ClientsCtrl.login({/*tosUrl: ''*/}, params.clientId, null, params).then(function (apiKey) {
        var oauthClient = apiKey.oauthClient;
        //console.log('DEBUG oauthClient', oauthClient);
        //console.log('DEBUG oauthClient.secret', !!oauthClient.secret);
        return LoginsCtrl.rawAccountIds({
          id: scoper.unscope(tokenMeta.idx, oauthClient.secret)
        }).then(function (accounts) {
          var axs = (accounts||[]).map(function (a) {
            //console.log('DEBUG account', a);
            return a && { appScopedId: scoper.scope(a.id, oauthClient.secret) };
          });
          // TODO make sure the acx still exists
          /*
          tokenMeta.acx = login.primaryAccountId && {
            id: scoper.scope(login.primaryAccountId, oauthClient.secret)
          };
          */

          return exchangeRefreshTokenHelper(params, params.refreshToken, tokenMeta, axs);
        });
      });
    });
  }



  /**
   * GrantTypePasswordExchange
   *
   * Given an authentic API Client and User, grant a token with the requested scope
   */
  function createRefreshTokenHelper(auth, params, axs, grantType, expiresIn) {
    var code = params.codeMeta || {};
    var rootClient = auth.rootClient;
    var apiKey = auth.apiKey;
    var oauthClient = auth.oauthClient || apiKey.oauthClient;
    var login = auth.login;
    var issuedAt;
    var tokenMeta;
    //var refreshToken; // = undefined
    var expiresAt;
    var sub;

    // TODO
    // the app should not be able to request scope greater than
    // what has been granted through the noraml oauth flow
    // (or specially granted by an admin)

    // TODO include MFA
    issuedAt = Math.floor(Date.now() / 1000);
    //expiresIn = 30 * 24 * 60 * 60; // 30 days
    //expiresAt = new Date(Date.now() + (expiresIn * 1000)).toISOString();
    expiresAt = new Date(Date.now() + (expiresIn * 1000)).valueOf();

    if (Array.isArray(axs)) {
      sub = axs.map(mapSubIds).filter(elementExists).join(',');
    }
    else {
      sub = code.sub || params.sub || params.acx && params.acx.appScopedId;
    }

    //console.log('[oauth3orize] apiKey', apiKey);
    tokenMeta = {
      // standard
      jti: crypto.randomBytes(16).toString('hex')
    , iat: issuedAt
    , iss: rootClient.url   // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.1
    , aud: rootClient.url   // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.3
    , azp: oauthClient.url
    , sub: code.sub || sub  // https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32#section-4.1.2
    , exp: code.exp || Math.floor(expiresAt / 1000)
    , nbf: code.nbf || undefined  // not before... weird
    , kid: code.kid || undefined  // key id

      // extended
    , scp: code.scp || (params.scope||[]).join(' ')                             // acceptedScopeString
    , as: 'account'
    , grt: grantType || 'password'                                                // grantType
      // this refresh token may only be used by the server if true
    , srv: code.srv || (apiKey.server && oauthClient.server) || !(apiKey.insecure || oauthClient.insecure)

      // backwards compat / extended
    , k: code.k || apiKey.id || apiKey.key                                        // apiKeyId
      // (would this not always also be the issuer?)
    , app: oauthClient.id                                                         // oauthClientId
    , acx: code.acx || axs[0]
    , axs: code.axs || axs

    // for testing, not for actionable normal use
    , test: apiKey.test || oauthClient.test || undefined

    //, requestedScopeString: params.scope.join(' ')
    };

    if (login) {
      tokenMeta.usr = login.id || login.hashId;                                               // loginId
      tokenMeta.acc = login.primaryAccountId && { id: login.primaryAccountId };               // selectedAccountId
      tokenMeta.acs = (login.accountIds||[]).map(function (a) { return a && { id: a.id }; });
      //tokenMeta.id = login.id;                                                                // loginId
      tokenMeta.idx = scoper.scope(login.id || login.hashId, oauthClient.secret);             // loginId
      tokenMeta.acx = login.primaryAccountId && {                                             // selectedAccountId
        id: scoper.scope(login.primaryAccountId, oauthClient.secret)
      };
      tokenMeta.as = 'login';
    }

    // this in turn causes the sha256 id to change
    tokenMeta.refresh = true;
    tokenMeta.exp = undefined;

    return tokenMeta;
  }
  function createRefreshToken(auth, params, axs, grantType) {
    var expiresIn = 30 * 24 * 60 * 60; // 30 days
    var tokenMeta = createRefreshTokenHelper(auth, params, axs, grantType, expiresIn);

    return Signer.sign(tokenMeta).then(function (refreshToken) {
      var id = authutils.hashsum('sha256', refreshToken);
      return TokenStore.create({
        id: id

      , expiresAt: tokenMeta.exp
      , issuedAt: tokenMeta.iat

      , scope: tokenMeta.scp
      , test: tokenMeta.test

        // sanity check session on renewal
      , userAgent: params.userAgent
      , ip: params.ip
      , origin: params.origin
      , referer: params.referer
      , isDeviceClient: !(params.origin || params.referer) || undefined
      , secure: params.secure

      , refreshToken: refreshToken
      }).then(function () {
        return {
          refreshToken: refreshToken
        , expiresAt: tokenMeta.exp
        , expiresIn: expiresIn
        , tokenType: 'refresh'
        , axs: axs
        , tokenMeta: tokenMeta
        };
      });
    });
  }

  function exchangePasswordToken(auth, params) {
    var err;
    var axs = (auth.login && auth.login.accountIds || []).map(function (a) {
      return a && { appScopedId: scoper.scope(a.id, auth.oauthClient.secret) };
    }).filter(elementExists);

    // TODO Trusted Clients
    // Check params.origin, params.referer (browser) or params.cname, params.ip (server)
    if (!auth.apiKey.test && !auth.oauthClient.root && 'groot' !== auth.oauthClient.accountId) {
      auth.apiKey.key = '[scrubbed]';
      if (auth.apiKey.secret) {
        auth.apiKey.secret = '[scrubbed]';
      }
      if (auth.oauthClient.secret) {
        auth.oauthClient.secret = '[scrubbed]';
      }

      console.warn('apiKey', auth.apiKey);
      console.warn('oauthClient', auth.oauthClient);
      err = new Error("trusted client checking not yet implemented (only allowed in test apps for now)");
      err.code = "E_NOT_IMPLEMENTED";
      return PromiseA.reject(err);
    }

    // auth = { rootClient, oauthClient, apiKey, login, accounts }
    // params = { }
    return createRefreshToken(auth, params, axs, 'password').then(function (refreshResult) {
      return exchangeRefreshTokenHelper(
        params
      , refreshResult.refreshToken
      , refreshResult.tokenMeta
      , refreshResult.axs
      ).then(function (tokenResult) {
        return {
          accessToken: tokenResult.accessToken
        , expiresIn: tokenResult.expiresIn
        , expiresAt: tokenResult.expiresAt
        , scope: refreshResult.tokenMeta.scp
        , tokenType: 'bearer'
        , refreshToken: refreshResult.refreshToken
        , refreshExpiresIn: refreshResult.refreshExpiresIn
        , refreshExpiresAt: refreshResult.refreshExpiresAt
        };
      });
    });
  }

  // grant_type=['client_credentials', 'password', 'delegated', 'authorization_code', 'implicit', 'refresh_token']
  // response_type=['code', 'token']
  function parseResourceOwnerPassword(req/*, opts*/) {
    var params = req.body;
    var err;

    if (!params) {
      err = new Error("grant_type 'password' is missing parameters object");
      err.code = 'E_MISSING_PARAM';
      return PromiseA.reject(err);
    }
    else if (!(params.client_id || params.clientId)) {
      err = new Error("grant_type 'password' is missing 'client_id' parameter");
      err.code = 'E_MISSING_PARAM';
      return PromiseA.reject(err);
    }
    else if (!params.username) {
      err = new Error("grant_type 'password' is missing 'username' parameter");
      err.code = 'E_MISSING_PARAM';
      return PromiseA.reject(err);
    }
    else if (!params.password) {
      err = new Error("grant_type 'password' is missing 'password' parameter"
        + " (misnomer: password refers to the secret, passphrase, or other authentication token)");
      err.code = 'E_MISSING_PARAM';
      return PromiseA.reject(err);
    }

    return PromiseA.resolve({
      rootClient: myRootClient

    , clientId: params.client_id || params.clientId
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
    , isDeviceClient: !(req.headers.origin || req.headers.referer)

    , ip: req.ip || req.socket.remoteAddress
    , userAgent: req.headers['user-agent']

    , secure: req.secure || 'https' === req.protocol || req.socket.encrypted
    });
    // TODO? sms MFA
    // TODO? qr-based MFA
  }

  // response_type=['authorization_code']
  function parseRefreshToken(req/*, opts*/) {
    var params = req.body;
    var err;

    if (!params) {
      err = new Error("grant_type 'refresh_token' is missing parameters object");
      err.code = 'E_MISSING_PARAM';
      return PromiseA.reject(err);
    }
    else if (!(params.client_id || params.clientId)) {
      err = new Error("grant_type 'refresh_token' is missing 'client_id' parameter");
      err.code = 'E_MISSING_PARAM';
      return PromiseA.reject(err);
    }
    else if (!(params.refresh_token || params.refreshToken)) {
      err = new Error("grant_type 'refresh_token' is missing 'refresh_token' parameter");
      err.code = 'E_MISSING_PARAM';
      return PromiseA.reject(err);
    }

    return PromiseA.resolve({
      rootClient: myRootClient

    , clientId: params.client_id || params.clientId
    , clientSecret: params.client_secret || params.clientSecret
    , clientUri: params.client_uri
    , refreshToken: params.refresh_token || params.refreshToken

      // since OAuth3 is federated tenants shouldn't be necessary... right?
    , tenantId: params.tenant_id || params.tenantId
    , scope: (params.scope||'').split(/\s+/g).filter(function (str) { return str; })

    , experienceId: req.experienceId || req.headers.origin || req.headers.referer
    , origin: req.headers.origin
    , referer: req.headers.referer
    , isDeviceClient: !(req.headers.origin || req.headers.referer)
    , ip: req.ip || req.socket.remoteAddress
    , userAgent: req.headers['user-agent']

    , secure: req.secure || 'https' === req.protocol || req.socket.encrypted
    });
    // TODO? sms MFA
    // TODO? qr-based MFA
  }

  function parseRegisterClient(req/*, opts*/) {
    //var jwt = PromiseA.promisifyAll(require('jsonwebtoken'));
    //var params = req.body;
    var hostname = (req.experienceId || req.hostname || req.headers.host || '')
      .replace(/^https?:\/\//, '').split(':').shift();
    var token = req.oauth3.token;
    var err;

    //console.log('DEBUG parseRegisterClient token:');
    //console.log(token);

    // TODO lookup issuer ip address and makesure it matches req.ip
    if (!token.iss) {
      err = new Error("issuer 'iss' is missing from token object (this should be your server api)");
      err.code = 'E_MISSING_PARAM';
      return PromiseA.reject(err);
    }

    if (!token.azp) {
      err = new Error("authorized party 'azp' is missing from the token object (this should be your browser app)");
      err.code = 'E_MISSING_PARAM';
      return PromiseA.reject(err);
    }

    if (token.sub && token.azp !== 'https://' + token.sub) {
      err = new Error("subject 'sub' (acting as client id/uri) should be"
        + " the same as 'azp' (client uri) without the scheme (https://)"
        + " or it should be left blank (generate random client id)");
      err.code = 'E_BAD_PARAM';
      return PromiseA.reject(err);
    }

    if (-1 === (token.aud || '').split(',').indexOf('https://' + hostname)) {
      err = new Error("audience `aud` '" + token.aud + "'(acting as provider uri)"
        + " should match the hostname '" + hostname + "'.");
      err.code = 'E_BAD_PARAM';
      return PromiseA.reject(err);
    }

    return PromiseA.resolve({
      rootClient: myRootClient

    , clientId: token.azp
    , clientSecret: ''
    , clientUri: token.azp

      // since OAuth3 is federated tenants shouldn't be necessary... right?
    , tenantId: token.tn
    , scope: (token.scp || '').split(/\s+/g).filter(function (str) { return str; })

    , kid: token.kid
    , token: token
    , encodedToken: req.oauth3.encodedToken

    , experienceId: req.experienceId || req.headers.origin || req.headers.referer
    , origin: req.headers.origin
    , referer: req.headers.referer

    , isDeviceClient: !(req.headers.origin || req.headers.referer)
    , ip: req.ip || req.socket.remoteAddress
    , userAgent: req.headers['user-agent']

    , secure: req.secure || 'https' === req.protocol || req.socket.encrypted
    });
  }

  function requestJson(opts) {
    var requestAsync = PromiseA.promisify(require('request'));

    return requestAsync({
      url: opts.url
    , headers: opts.headers || { 'Accept': 'application/json; charset=utf-8' }
    }).then(function (resp) {
      //var data = resp.body;
      //console.log('DEBUG client key checking');
      //console.log(data);

      if (200 !== resp.statusCode) {
        return PromiseA.reject(new Error(
          "'" + opts.url + "' did not complete successfully: "
        + resp.statusCode + " " + resp.body
        ));
      }

      if ('string' === typeof resp.body) {
        resp.body = JSON.parse(resp.body);
      }

      return resp;
    });
  }

  function registerClient(params/* opts*/) {
    /*
    // actually, we don't need to check the origin / referer here because it's server-to-server
    if (!ClientsCtrl.checkOrigin([params.clientUri], params.origin, params.referer)) {
      return PromiseA.reject(new Error(
        "'" + params.clientUri + "' does not match"
      + " '" + (params.origin || params.referer) + "'")
      );
    }
    */

    var url = params.clientUri + '/.well-known/oauth3.json';

    //console.log('DEBUG oauth3.json url', url);
    return requestJson({ url: url }).then(function (resp) {
      var data = resp.body;
      var keysUrl;

      if (!data.jwks_uri && !data.jwksUri) {
        return PromiseA.reject(new Error("'" + url + "' does not specify jwks_uri"));
      }

      keysUrl = (data.jwks_uri || data.jwksUri)
        .replace(/:client_uri/g, params.clientUri.replace(/^https:\/\//, ''))
        .replace(/:kid/g, params.token.kid || '')
      ;

      // TODO maybe check jwks_uri against iss ?
      //console.log('DEBUG keysUrl', keysUrl);
      return requestJson({ url: keysUrl }).then(function (resp) {
        var data = resp.body;
        var keys = data && data.keys || [];
        var pubKeyPem;
        var jwt;
        var jwk;

        if (data && data.kid) {
          jwk = data;
        }
        else {
          if (!(data && Array.isArray(data.keys) && data.keys.length)) {
            return PromiseA.reject(new Error("no array of keys"));
          }

          jwk = keys.filter(function (k) {
            return k.kid === params.token.kid;
          })[0] || keys[0];
        }

        if (!jwk) {
          return PromiseA.reject(new Error("public key could not be found by key id '" + params.token.kid + "'"));
        }

        pubKeyPem = require('ursa').createPublicKeyFromComponents(
          new Buffer(jwk.n, 'base64') // modulus
        , new Buffer(jwk.e, 'base64') // exponent
        ).toPublicPem();

        // verify token
        jwt = PromiseA.promisifyAll(require('jsonwebtoken'));
        return jwt.verifyAsync(params.encodedToken, pubKeyPem).then(function () {
          //console.log('DEBUG call registerApiKey (pre-entry point)');
          return ClientsCtrl.registerApiKey(null, pubKeyPem, jwk, params);
        });
      });
    });
  }



  function parseAuthorizationCode(req/*, opts*/) {
    // TODO pull client id, client secret, redirect_uri, and code?
    var encoded = req.body.code || req.query.code;
    var experienceId = req.experienceId || req.headers.origin || req.headers.referer;

    return PromiseA.resolve({
      experienceId: experienceId
    , code: encoded
    , redirectUri: req.body.redirectUri || req.body.redirect_uri
        || req.query.redirect_uri
    , clientUri: undefined /*code.azp*/
    , clientId: req.body.clientId || req.body.client_id
        || req.query.client_id
    , clientSecret: req.body.clientSecret || req.body.client_secret
        || req.query.client_secret
    , tenantId: req.body.tentantId || req.body.tenant_id
        || req.query.tenant_id
    , ip: req.ip || req.socket.remoteAddress
    });
  }
  function exchangeAuthorizationCode(params/*, opts*/) {
    return ClientsCtrl.login(
      {/*tosUrl: ''*/}
    , params.clientId
    , params.clientSecret || 'fail-on-purpose'
    , params
    ).then(function (apiKey) {
      var oauthClient = apiKey.oauthClient;

      return Signer.verifyAsync(params.experienceId, params.code).then(function (codeMeta) {
        var auth = {
          apiKey: apiKey
        , oauthClient: oauthClient
        , rootClient: myRootClient

        , login: null
        , ppid: codeMeta.sub
        };
        /*
        var axs = (login.accountIds||[]).map(function (a) {
          return a && { appScopedId: scoper.scope(a.id, oauthClient.secret) };
        });
        */

        //console.log('[DEBUG] codeMeta:');
        //console.log(codeMeta);

        var axs = codeMeta.axs || [
          { ppid: codeMeta.ppid
          , sub: codeMeta.sub
          , id: codeMeta.ppid || codeMeta.sub || codeMeta.appScopedId || codeMeta.acx.id
          , appScopedId: codeMeta.ppid || codeMeta.sub || codeMeta.appScopedId || codeMeta.acx.id
          }
        ];
        params.codeMeta = codeMeta;
        codeMeta.axs = codeMeta.axs || axs;
        return createRefreshToken(auth, params, null, 'code').then(function (refreshResult) {
          // TODO check azp against client_id / client_uri / apikey_id

          return exchangeRefreshTokenHelper(
            params
          , refreshResult.refreshToken
          , refreshResult.tokenMeta
          , refreshResult.axs
          ).then(function (tokenResult) {
            return {
              accessToken: tokenResult.accessToken
            , expiresIn: tokenResult.expiresIn
            , expiresAt: tokenResult.expiresAt
            , scope: refreshResult.tokenMeta.scp
            , tokenType: 'bearer'
            , refreshToken: refreshResult.refreshToken
            , refreshExpiresIn: refreshResult.refreshExpiresIn
            , refreshExpiresAt: refreshResult.refreshExpiresAt
            };
          });
        });
      });
    });
  }

  /**
   * Internal Implementation for granting of 'code' and 'token'
   *
   * The end goal:
   *   Each user will have a key pair on each device (or browser)
   *   which keypair will sign codes and tokens.
   *   Only when the user is using a public device (library computer)
   *   will the root provider token be used.
   *   The server will only be used to store grants (to be shared between computers)
   *   if that's what the user wishes.
   * The now goal:
   *   As an interim solution we handle the signing of codes and tokens
   *   completely on the server, but we allow all of the UI for permission
   *   grants to exist in the browser.
   */
  function grantAuthorizationCodeHelper(req, opts) {
    // Uses jwt model of
    // ../packages/apis/org.oauth3.consumer/lib/token-signer.js
    // ../packages/apis/org.oauth3.consumer/lib/config-store.js

    // TODO include MFA and auth_time

    var issuedAt = Math.floor(Date.now() / 1000);
    var expiresIn = 5 * 60; // 30 minutes
    var expiresAt = new Date(Date.now() + (expiresIn * 1000)).valueOf();

    var rootClient = myRootClient;
    var oauthClient = opts.oauthClient || {};
    var apiKey = opts.apiKey || {};
    var sub = opts.sub || opts.ppid; // scoped to oauthClient.secret, not rootClient.secret

    // TODO issuing client rather than blanked "root client"
    sub = scoper.scope(scoper.unscope(sub, rootClient.secret), oauthClient.secret);

    //console.log("[DEBUG] grantCode opts:");
    //console.log(opts);

    //console.log('[oauth3orize] apiKey', apiKey);
    var codeMeta = {
      // standard
      jti: crypto.randomBytes(16).toString('hex')
    , exp: Math.floor(expiresAt / 1000)
    , iat: issuedAt
    , nbf: undefined        // not before... weird
    , iss: rootClient.url   // root client (on this server) is issuing
    , aud: rootClient.url   // this token is only intended for the root client (on this server)
    , azp: oauthClient.url  // this token may only be used by the 3rd party client (from their server)
    , srv: true             // authorization code is server-only by definition
    , sub: sub

      // extended
    , as: 'account'
    , typ: 'code'
    , grt: 'code'

      // backwards compat & extended
    , k:   apiKey.id || apiKey.key                                                // apiKeyId
      // (would this not always also be the issuer?)
    , app: oauthClient.id                                                         // oauthClientId
    , acx: { appScopedId: sub }                                                   // selectedAccountId
    , scp: opts.scope                                                             // TODO acceptedScopeString


    // for testing, not for actionable normal use
    , test: apiKey.test || oauthClient.test || undefined

    //, requestedScopeString: params.scope.join(' ')
    };

    //console.log('[DEBUG] grantCode codeMeta:');
    //console.log(codeMeta);
    return codeMeta;
  }
  function grantAuthorizationCode(req, opts) {
    var codeMeta = grantAuthorizationCodeHelper(req, opts);

    return {
      code: Signer.sign(codeMeta)
    };
  }
  function grantAccessToken(req, opts) {
    var codeMeta = grantAuthorizationCodeHelper(req, opts);
    var auth = {
      oauthClient: opts.oauthClient
    , apiKey: opts.apiKey
    , rootClient: myRootClient

    , login: null
    , ppid: codeMeta.sub
    , sub: codeMeta.sub
    };
    var grantType = 'token'; // TODO better name? just use 'token'? 'implicit'?
    var params = opts;

    params.codeMeta = codeMeta;
    return createRefreshToken(auth, params, null, grantType).then(function (refreshResult) {
      return exchangeRefreshTokenHelper(
        params
      , refreshResult.refreshToken
      , refreshResult.tokenMeta
      , refreshResult.axs
      ).then(function (tokenResult) {
        return {
          accessToken: tokenResult.accessToken
        , expiresIn: tokenResult.expiresIn
        , expiresAt: tokenResult.expiresAt
        , scope: refreshResult.tokenMeta.scp
        , tokenType: 'bearer'
        , refreshToken: refreshResult.refreshToken
        , refreshExpiresIn: refreshResult.refreshExpiresIn
        , refreshExpiresAt: refreshResult.refreshExpiresAt
        };
      });
    });
  }



  /**
   * notImplemented
   *
   * because hey, might as well, right?
   */
  function notImplemented() {
    return PromiseA.reject(new Error("Not Implemented"));
  }

  return {
    parseRegisterClient: parseRegisterClient
  , parseResourceOwnerPassword: parseResourceOwnerPassword
  , parseRefreshToken: parseRefreshToken
  , parseAuthorizationCode: parseAuthorizationCode
  , exchangePasswordToken: exchangePasswordToken
  , exchangeRefreshToken: exchangeRefreshToken
  , exchangeAuthorizationCode: exchangeAuthorizationCode
  , getClientAndUser: getClientAndUser
  , registerClient: registerClient
  , grantAuthorizationCode: grantAuthorizationCode
  , grantAccessToken: grantAccessToken
  , noImpl: notImplemented
  };
};
