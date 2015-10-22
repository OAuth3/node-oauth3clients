'use strict';

var PromiseA = require('bluebird').Promise;

module.exports.create = function (OauthClients, Logins, GrantStore, TokenStore, Signer) {

  /**
   * ResourceOwnerPasswordStrategy
   *
   * This strategy is used to authenticate registered OAuth clients WITH users'
   * credentials. It is employed to protect the `token` endpoint, which consumers
   * use to obtain access tokens on behalf of the users supplying credentials.
   * This is primary for use with privileged applications in insecure environments
   * (such as an official mobile app)
   */
  function getClientAndUser(apiKeyId, apiKeySecret, user, secret/*, opts*/) {
    // TODO origin / referer
    return OauthClients.login(null, apiKeyId, apiKeySecret).then(function (apiKey) {
      //TODO Logins.login()
      return { apiKey: apiKey, username: user, secret: secret };
    }, function (err) {
      if (/Incorrect/i.test(err && err.message)) {
        return { apiKey: null, username: null, secret: null };
      } else {
        console.error('[ERROR] getClientAndUser [resource owner password] - Unknown');
        console.warn(err);
        console.warn(err.stack);

        return PromiseA.reject(err);
      }
    }).catch(function (err) {
      console.warn(err);
      console.warn(err.stack);
      throw err;
    });
  }

  /**
   * GrantTypePasswordExchange
   *
   * Given an authentic API Client and User, grant a token with the requested scope
   */
  function exchangePasswordToken(result) {
    var apiKey = result.apiKey || result.apikey;
    var username = result.username;
    var passphrase = result.secret;
    var scopeArr = result.scope;

    // NOTE: this userProperty is 'user' because passport is directly handling the strategy
    // console.log('[E] grant_type=password]');
    scopeArr = scopeArr || [];

    // TODO
    // the app should not be able to request scope greater than
    // what has been granted through the noraml oauth flow
    // (or specially granted by an admin)

    // TODO double check referer (browser) and ip (server)?... somehow...
    // $ = .related('oauthclient')
    var oauthClient = apiKey.oauthClient;
    if (!apiKey.test && !oauthClient.root && 'groot' !== oauthClient.accountId) {
      console.log('apiKey', apiKey.toJSON());
      console.log('oauthClient', oauthClient.toJSON());
      return PromiseA.reject(new Error("trusted client checking not yet implemented (only allowed in test apps for now)"));
    }

    // Validate the user
    // This type of validation can be used in the (rare) case that users are application specific
    // Or if the application is the root application
    return Logins.login('username', username, passphrase, {
      // NOTE: if the service allows apps to create their own users,
      // the app id would help distinguish between them
      // (and the type could change to 'app-scoped')
      oaouthClientId: oauthClient.id
    //, $oauthclient: $client
    , apiKeyId: apiKey.id
    //, $apikey: $apikey
    }).then(function (login) {
      var tokenMeta;
      //var refreshToken; // = undefined
      var expiresAt;
      var params;

      if (null === login) {
        return null;
      }

      expiresAt = new Date(Date.now() + (30 * 24 * 60 * 60 * 1000)).toISOString();
      params = { expires_at: expiresAt, login_id: login.id };
      // TODO [JWT] squish all of this into a JWT
      tokenMeta = {
        apiKeyId: apiKey.id
      , oauthClientId: oauthClient.id
      , loginId: login.id
      , expiresAt: expiresAt
      , selectedAccountId: login.primaryAccountId
      , accounts: login.accounts.map(function (a) { return a; })
      , requestedScopeString: scopeArr.join(' ')
      , acceptedScopeString: scopeArr.join(' ') // TODO test accepted scope against allowed scope
      , test: apiKey.test || oauthClient.test
      , insecure: apiKey.insecure || oauthClient.insecure
      , as: 'login'
      , grantType: 'password' // resource owner password
      };

      return Signer.sign(tokenMeta).then(function (jwt) {
        // TODO accounts.forEach
        return Tokens.create({
          id: sha256(jwt)
        //, accountId: accounts && accounts[0] && accounts[0].id
        , loginId: login.id
        , expiresAt: expiresAt
        , oauthClientId: oauthClient.id
        , token: jwt
        });
      });

      /*
      return AccessTokens.create(tokenMeta).then(function (token) {
        params.granted_scopes = scopeArr.join(',').trim().replace(/\s+/g, ',');

        return { token: token.token, refreshToken: refreshToken, params: params };
      }, function (err) {
        console.error("[ERROR] [exchange password] couldn't create AccessToken");
        console.error(err);

        return PromiseA.reject(err || new Error('no error given')); // no soft exceptions (to be caught)
      }).catch(function (err) {
        console.error("[ERROR] [exchange password] couldn't create AccessToken");
        console.error(err);
        console.error(err.message);
        console.error(err.stack);

        throw err;
      });
      */
    }, function (err) {
      // authentication failed
      if (err.code === 'ETIMEDOUT') {
        // err.connect // was TCP issues
        throw err;
      }

      return PromiseA.reject(err);
    }).catch(function (err) {
      console.error("[ERROR] [exchange password] couldn't authenticate");
      console.error(err);

      throw err;
    });
  }

  // grant_type=['client_credentials', 'password', 'delegated', 'code', 'implicit']
  // response_type=['authorization_code']
  function parseResourceOwnerPassword(params, opts) {
    if (!params) {
      return PromiseA.reject(new Error("grant_type 'password' is missing parameters object"));
    }
    else if (!params.client_id) {
      return PromiseA.reject(new Error("grant_type 'password' is missing 'client_id' parameter"));
    }
    else if (!params.username) {
      return PromiseA.reject(new Error("grant_type 'password' is missing 'username' parameter"));
    }
    else if (!params.password) {
      return PromiseA.reject(new Error("grant_type 'password' is missing 'password' parameter (misnomer: password refers to the secret, passphrase, or other authentication token)"));
    }

    var clientId = params.client_id;
    var clientSecret = params.client_secret;
    var userId = params.username;
    var userSecret = params.password;

    return getClientAndUser(clientId, clientSecret, userId, userSecret, opts).then(function (result) {
      result.scope = params.scope.split(/\s+/g).filter(function (str) { return str; });
      result.origin = opts._request.headers.origin;
      result.referer = opts._request.headers.referer;

      return result;
    });
  }

  return {
    resourceOwnerPassword: {
      parse: parseResourceOwnerPassword
    , exchange: exchangePasswordToken
    }
  };
};
