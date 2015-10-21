'use strict';

/*global Promise*/
var PromiseA = Promise;
try {
  PromiseA = require('bluebird').Promise;
} catch (e) {
  // ignore
}

var config = require('../config.test.js');

function dbsetup() {
  var sqlite3 = require('sqlite3-cluster');
  var wrap = require('dbwrap');

  var dir = [
    { tablename: 'logins' // coolaj86, coolaj86@gmail.com, +1-317-426-6525
    , idname: 'hashId'
    //, relations: [{ tablename: 'secrets', id: 'hashid', fk: 'loginId' }]
    , indices: ['createdAt', 'type', 'node']
    //, immutable: false
    }
  , { tablename: 'api_keys'
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt', 'oauthClientId']
    , schema: function () {
        return {
          test: true
        , insecure: true
        };
      }
    }
  , { tablename: 'oauth_clients'
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt']
    , hasMany: ['apiKeys'] // TODO
    , schema: function () {
        return {
          test: true
        , insecure: true
        };
      }
    }
  , { tablename: 'oauthorizations'
    , modelname: 'Authorizations'
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt']
    }
  , { tablename: 'private_key'
    , idname: 'id'
    , indices: ['createdAt']
    }
  ];

  var promise = sqlite3.create({
      standalone: true
    , bits: 128
    , filename: config.filename
    , verbose: false
  });

  return promise.then(function (db) {
    return db.init({ bits: 128, key: config.key });
  }).then(function (db) {
    return wrap.wrap(db, dir);
  });
}

function init(Kv, models, signer, OauthClients) {
  var tests;
  var count = 0;

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
        console.log('pem private key', key);
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

      return OauthClients.create(null, account, client).then(function (client) {
        console.log('client', client);
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

module.exports.create = function () {
  var cstore = require('cluster-store');
  var Signer = require('../lib/sign-token');
  var OauthClients = require('../lib/oauthclients');

  // TODO cluster.isMaster should init the session store
  return cstore.create({ standalone: true, store: new require('express-session/session/memory')() }).then(function (Kv) {
    return dbsetup().then(function (DB) {
      // TODO cluster.isMaster should init the signer
      return Signer.create(DB.PrivateKey).init().then(function (signer) {

        var oauthclients = OauthClients.createController({}, DB, signer);
        return init(
          PromiseA.promisifyAll(Kv), DB, signer, oauthclients
          //Kv, require('../lib/logins').create({}, require('authcodes').create(DB.Codes), DB)
        );
      });
    });
  });
};

module.exports.create();
