'use strict';

var PromiseA = require('bluebird').Promise;

var cstore = require('cluster-store');
var Signer = require('../lib/sign-token');
var OauthClients = require('../lib/oauthclients');
var Oauth3orize = require('../lib/oauth3orize');

function dbsetup(config) {
  var sqlite3 = require('sqlite3-cluster');
  var wrap = require('dbwrap');

  var dir = [
    { tablename: 'private_key'
    , idname: 'id'
    , indices: ['createdAt']
    }
  , { tablename: 'oauth_clients'
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt', 'accountId']
    , hasMany: ['apiKeys'] // TODO
    , belongsTo: ['account']
    , schema: function () {
        return {
          test: true
        , insecure: true
        };
      }
    }
  , { tablename: 'api_keys'
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt', 'oauthClientId']
    , belongsTo: ['oauthClient'] // TODO pluralization
    , schema: function () {
        return {
          test: true
        , insecure: true
        };
      }
    }
  , { tablename: 'tokens' // note that a token functions as a session
    , idname: 'id'
    , indices: ['createdAt', 'updatedAt', 'expiresAt', 'revokedAt', 'oauthClientId', 'loginId', 'accountId']
    }
  , { tablename: 'grants'
    , idname: 'id' // sha256(scope + oauthClientId + (accountId || loginId))
    , indices: ['createdAt', 'updatedAt', 'oauthClientId', 'loginId', 'accountId']
    }

    //
    // Specific to Logins Implementation, not OAuth3 stuff
    //
  , { tablename: 'codes'
    , idname: 'uuid'
    , indices: ['createdAt']
    }
  , { tablename: 'logins' // coolaj86, coolaj86@gmail.com, +1-317-426-6525
    , idname: 'hashId'
    //, relations: [{ tablename: 'secrets', id: 'hashid', fk: 'loginId' }]
    , indices: ['createdAt', 'type', 'node']
    //, immutable: false
    }
  , { tablename: 'verifications'
    , idname: 'hashId' // hash(date + node)
    //, relations: [{ tablename: 'secrets', id: 'hashid', fk: 'loginId' }]
    , indices: ['createdAt', 'nodeId']
    //, immutable: true
    }
  , { tablename: 'secrets'
    , idname: 'hashId' // hash(node + secret)
    , indices: ['createdAt']
    //, immutable: true
    }
  , { tablename: 'recoveryNodes' // just for 1st-party logins
    , idname: 'hashId' //
      // TODO how transmit that something should be deleted / disabled?
    , indices: ['createdAt', 'updatedAt', 'loginHash', 'recoveryNode', 'deleted']
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

module.exports.create = function (config) {
  // TODO cluster.isMaster should init the session store
  return cstore.create({ standalone: true, store: new require('express-session/session/memory')() }).then(function (Kv) {
    return dbsetup(config).then(function (DB) {
      // TODO cluster.isMaster should init the signer

      var CodesCtrl = require('authcodes').create(DB.Codes);
      var LoginsCtrl = require('../../authentication-microservice/lib/logins').create({}, CodesCtrl, DB);
      return require('./login-helper').create(config, DB, LoginsCtrl).then(function (result) {
        var user = result;

        return Signer.create(DB.PrivateKey).init().then(function (signer) {

          var ClientsCtrl = OauthClients.createController({}, DB, signer);
          var oauth3orize = Oauth3orize.create(config, DB.Tokens, ClientsCtrl, LoginsCtrl, signer);
          return {
            Kv: PromiseA.promisifyAll(Kv)
          , Db: DB
          , LoginsCtrl: LoginsCtrl
          , Signer: signer
          , ClientsCtrl: ClientsCtrl
          , user: user
          , oauth3orize: oauth3orize
          };
        });
      });
    });
  });
};
