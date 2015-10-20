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
  , { tablename: 'oauthorizations'
    , modelname: 'Authorizations'
    , idname: 'hashId'
    , indices: ['createdAt', 'nodeId']
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

function init(Kv, models, signer) {
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

  return cstore.create({ standalone: true, store: new require('express-session/session/memory')() }).then(function (Kv) {
    console.log('a');
    return dbsetup().then(function (DB) {
      console.log('b');
      return Signer.create(DB.PrivateKey).init().then(function (signer) {
        console.log('c');
        return init(
          PromiseA.promisifyAll(Kv), DB, signer//, require('../lib/tokens').create({}, DB)
          //Kv, require('../lib/logins').create({}, require('authcodes').create(DB.Codes), DB)
        );
      });
    });
  });
};

module.exports.create();
