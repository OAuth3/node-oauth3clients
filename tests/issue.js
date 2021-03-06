'use strict';

var PromiseA = require('bluebird').Promise;
var assert = require('assert');

var config = require('../config.test.js');

function run(Kv, models, LoginsCtrl, signer, ClientsCtrl, user, oauth3orize) {
  var tests;
  var count = 0;
  var apikey = null;
  var parsedRequest;
  var clientAndUser;

  function setup() {
    return PromiseA.resolve();
  }

  function teardown() {
    return PromiseA.resolve();
  }

  // Test that success is successful
  tests = [
    function () {
      // test setup / teardown
      return PromiseA.resolve();
    }
  , function failMemDbGet() {
      return Kv.getAsync('abc').then(function (val) {
        if (val) {
          throw new Error('kv should not have value');
        }
        if (null !== val) {
          throw new Error('kv non-value should be `null`');
        }
      });
    }
  , function testMemDbSet() {
      return Kv.setAsync('abc', '123');
    }
  , function passMemDbGet() {
      return Kv.getAsync('abc').then(function (val) {
        if ('123' !== val) {
          throw new Error('kv should have value "123"');
        }
      });
    }
  , function passMemDbRemove() {
      return Kv.destroyAsync('abc').then(function () {
        return Kv.getAsync('abc').then(function (val) {
          if (null !== val) {
            throw new Error('kv should have been deleted');
          }
        });
      });
    }
  , function passCreatePrivateKey() {
      return signer.loadKey().then(function (key) {
        if (!key) {
          throw new Error("fail create private key");
        }
        if (!key.toPrivatePem()) {
          throw new Error("fail create private key pem");
        }
        if (!key.toPublicPem()) {
          throw new Error("fail create public key pem");
        }
      });
    }
  , function passCreatePrivateKey() {
      var account = {
        id: 'root'
      , iAmGroot: true
      };
      var client = {
        name: 'My Foo App'
      , desc: 'Upload foos and download corresponding bars!'
      , urls: ['https://foobarconverteronline.com', 'https://barfooconverteronline.com']
      , ips: [] // dynamic IPs??
      , publicKey: null // ??
      , logo: 'https://foobarconverteronline.com/images/logo-256px.png'
      , live: false // won't show up on app store
      , repo: 'git://github.com/coolaj86/foobarconverteronline'
      , keywords: [ 'foo', 'bar', 'converter', 'online' ]
      , insecure: true // do not produce server keys when true
      , status: 'active' // I don't even remember
      , test: true // also produce test keys
      , primary_id: null // account?
      , publishedAt: null // date gone live?
      , testers: [] // ??? accounts? logins? what?
      };

      return ClientsCtrl.create(null, account, client).then(function (client) {
        if (!client || !client.apiKeys) {
          return PromiseA.reject(new Error("did not create client with api keys"));
        }

        client.apiKeys.some(function (key) {
          if (key.test && key.insecure) {
            apikey = key;
            return true;
          }
        });
      });
    }
  , function passApiKeyLogin() {
      //var AppLogin = require('../lib/auth-logic/oauthclients').createController(/*config*/null, Db);
      return ClientsCtrl.login(null, apikey.key).then(function (apikey) {
        if (!apikey) {
          throw new Error("missing api key");
        }
        if (!apikey.oauthClient) {
          throw new Error("missing oauth client");
        }
      });
    }
  , function failApiKeyLogin() {
      return ClientsCtrl.login(null, apikey.key + '.').then(function (apikey) {
        var err;

        if (apikey) {
          err = new Error("succeeded client login with invalid credentials");
          err.code = 'E_FAIL';
          return PromiseA.reject(err);
        }
      }, function (err) {
        if ('E_INVALID_CLIENT_ID' === err.code) {
          return null;
        }

        console.error('[failApiKeyLogin]');
        console.error(err);
        console.error(err.stack);
        throw err;
      });
    }
  , function passUserLogin() {
      // this is just a sanity check, it's already tested in its own tests
      return LoginsCtrl.login({
        node: user.node
      , type: user.type
      , secret: user.secret
      });
    }
  , function getToken() {
      parsedRequest = {
        clientId: apikey.key
      , clientSecret: undefined // 'anonymous'
      , username: user.node
      , usernameType: undefined // user.type
      , password: user.secret

      , tenantId: undefined
      , scope: []

      , totp: undefined
      , mfa: undefined

      , origin: 'https://daplie.com'
      , referer: 'https://daplie.com/connect/'
      , userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) '
                    + 'AppleWebKit/537.36 (KHTML, like Gecko) '
                    + 'Chrome/45.0.2454.101 Safari/537.36'
      , ip: '127.0.0.1'
      , secure: true
      };

      return oauth3orize.parseResourceOwnerPassword({
        method: 'POST'
      , body: {
          client_id: apikey.key
        , client_secret: undefined // apikey.secret
        , username: user.node
        , password: user.secret
        , grant_type: 'password'
        }

      , headers: {
          origin: 'https://daplie.com'
        , referer: 'https://daplie.com/connect/'
        , 'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) '
                        + 'AppleWebKit/537.36 (KHTML, like Gecko) '
                        + 'Chrome/45.0.2454.101 Safari/537.36'
        }
      , socket: { encrypted: true, remoteAddress: '127.0.0.1' }

      , ip: '127.0.0.1'
      , protocol: 'https'
      , secure: true
      }).then(function (actual) {
        assert.deepEqual(actual, parsedRequest);
      });
    }
  , function passLoginWithClient() {
      // adds 'apiKey' and 'login'
      return oauth3orize.getClientAndUser(parsedRequest).then(function (cu) {
        clientAndUser = cu;
        if (!clientAndUser.apiKey) {
          throw new Error("key was not retrieved");
        }
        if (!clientAndUser.apiKey.oauthClient) {
          throw new Error("client was not retrieved");
        }
        if (!clientAndUser.login) {
          throw new Error("login was not retrieved");
        }
      });
    }
  , function passExchangePassword() {
      return oauth3orize.exchangePasswordToken(clientAndUser, parsedRequest).then(function (result) {
        if (!result.accessToken) {
          throw new Error("accessToken was not retrieved");
        }
        if (!result.refreshToken) {
          throw new Error("refreshToken was not granted");
        }
      });
    }
  , function notImplemented() {
      throw new Error('Not Implemented');
    }
  // TODO test a valid claim against an invalid account
  ];

  var testsLen = tests.length;
  var curFn;

  function phase1() {
    return new PromiseA(function (resolve) {

      function callDoStuff() {
        curFn = tests.shift();

        return doStuff(curFn, testsLen - tests.length).catch(function (err) {
          return teardown().then(function () {
            throw err;
          });
        }).error(function (err) {
          return teardown().then(function () {
            throw err;
          });
        });
      }

      function doStuff(fn/*, i*/) {
        if (!fn) {
          return PromiseA.resolve();
        }

        //console.log('i1', i);
        return setup().then(fn).then(teardown).then(function () {
          //console.log('i2', i, count);
          count += 1;

          return callDoStuff();
        });
      }

      callDoStuff().then(function () {
        resolve();
      }).catch(function (err) {
        console.error('[ERROR] failure');
        console.error(err);
        console.error(err.stack);
        console.error(curFn.toString());
        resolve();
      });
    });
  }

  phase1().then(function () {
    console.info('%d of %d tests complete', count, testsLen);
    process.exit();
  });
}

/*
            return initApi(config, LoginStore, Kv, Db, app);
function initApi(config, LoginStore, Kv, Db, app) {
  var loginsController = require('./lib/lds-logins').createController(config, LoginStore, Db, ContactNodes);
        var cstore = require('cluster-store');
        return cstore.create({ standalone: true, store: new require('express-session/session/memory')() }).then(function (Kv) {
          return require('./new-db').create().then(function (DbNew) {
*/

module.exports.create = function () {
  return require('./setup-helper').create(config).then(function (stuff) {
    return run(stuff.Kv, stuff.Db, stuff.LoginsCtrl, stuff.Signer, stuff.ClientsCtrl
      , stuff.user, stuff.oauth3orize);
  });
};

module.exports.create();
