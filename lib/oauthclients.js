'use strict';

// NOTES
// create and delete require the parent
// get and getAll are done in the require, which requires the parent as context
// (the view bits do not)
// update needs schema

var PromiseA = require('bluebird').Promise;
var crypto = require('crypto');
// var scoper = require('app-scoped-ids');

module.exports.createController = function (config, Db) {
  var UUID = require('node-uuid');
  var authutils = require('secret-utils'); // TODO use pbkdf2-utils instead
  var validate = require('./st-validate').validate;

  function OauthClients() {
  }

  OauthClients._getApiKeys = function (config, opts) {
    return Db.ApiKeys.get(opts.id || opts.clientUri).then(function (apiKey) {
      var err;

      if (apiKey) {
        return apiKey;
      }

      if (!opts.clientAgreeTos) {
        err = new Error("Incorrect Api Key");
        err.code = 'E_INVALID_CLIENT_ID';
        return PromiseA.reject(err);
      }

      if (opts.clientAgreeTos !== (config.tosUrl || 'oauth3.org/tos/draft')) {
        err = new Error("Incorrect Terms of Service URL");
        err.code = 'E_INVALID_TOS_URL';
        return PromiseA.reject(err);
      }

      /* TODO needs some sort of check */
      if (!(opts.origin || opts.referer || opts.clientUri)) {
        console.log('[oauthclients.js] DEBUG', opts);
        err = new Error("Incorrect clientUri");
        err.code = 'E_INVALID_CLIENT_URI';
        return PromiseA.reject(err);
      }
    });
  };

  OauthClients.genKeypair = function genKeypair(opts) {
    var crypto = require('crypto');
    var ursa = require('ursa');
    var bits = 1024;
    var mod = 65537; // seems to be the most common, not sure why
    var key;
    var pub = opts.publicKeyPem;
    var priv;

    if (!pub) {
      key = ursa.generatePrivateKey(bits, mod);
      pub = key.toPublicPem().toString();
      priv = key.toPrivatePem().toString();
    }

    return {
      // id needs to be unique, but multiple sites could use the same private key
      id: opts.id || crypto.createHash('sha256').update(opts.uri + pub).digest('hex')
    , pub: pub
      // TODO priv should only be saved by the client, not in the db
      // (however, this could be the client as well)
    , priv: priv
      // TODO this should be a proof / shadow, not a secret
    //, secret: crypto.randomBytes(16).toString('hex')
    , bits: bits
    , type: 'rsa'
    , alg: 'RS256'
    , server: opts.server || false
    , insecure: opts.insecure // deprecated (safe to remove here)
    //, cnames: []
    , urls: opts.urls     // allowed audiences (i.e. the requesting client exampleapp.com and examplepartner.com)
    , cnames: opts.cnames // allowed servers (instead of ips)
    , desc: opts.desc
    };
  };

  // This is the wrong place for this
  OauthClients._todoGetGrootTodo = function (experienceId, opts) {
    return Db.Accounts.get('groot').then(function (account) {
      if (account) {
        return account;
      }

      account = { id: 'groot', iAmGroot: true };

      if (opts.debug) {
        console.log('[Create User Profile]', experienceId);
      }

      return Db.Accounts.create(account.id, account).then(function () {
        return account;
      });
    });
  };

  // Note: this is the new method, the old one may not work
  OauthClients.createKeysHelper = function (opts, oauthClient, experienceId, clientUrlId, keyUrlId) {
    if (opts.debug) {
      console.log('[OAuth3 Client]', oauthClient.id, oauthClient);
    }

    return Db.ApiKeys.find({ oauthClientId: oauthClient.id, url: keyUrlId }).then(function (apiKeys) {
      var apiKey;

      if (!apiKeys.length) {
        if (opts.debug) {
          console.log('[Create API Key], ' + oauthClient.id + ', ' + keyUrlId);
        }

        apiKey = OauthClients.genKeypair({
          id: experienceId
        , uri: experienceId
        , server: false
        , insecure: true // deprecated (safe to remove here)
        , desc: 'Automatically provisioned client.'
        });
        apiKey.oauthClientId = oauthClient.id;
        apiKey.url = keyUrlId;

        return Db.ApiKeys.create(apiKey).then(function () {
          oauthClient.apiKeys = [apiKey];
          return oauthClient;
        });
      }

      oauthClient.apiKeys = apiKeys;
      return oauthClient;
    });
  };

  // Note: this is the new method, the old one may not work
  OauthClients.createHelper = function (account, clientUrlId) {
    // owned by the system account until claimed by the uri owner
    if (!account) {
      account = {
        id: 'groot'
      , iAmGroot: true
      };
    }
    var crypto = require('crypto');
    var client = {
      id: clientUrlId
    , url: clientUrlId
    , name: clientUrlId
    , root: account.iAmGroot
    , accountId: account.id
    , urls: ['https://' + clientUrlId]
    , cnames: [clientUrlId]
    , secret: crypto.randomBytes(16).toString('hex')
    };

    return OauthClients.create(client.id, client).then(function () {
      return client;
    });
    //return PromiseA.reject(new Error("Not Implemented"));
  };

  OauthClients.getOrCreateClient = function (config, opts) {
    var keyUrlId = opts.keyUrlId;
    var experienceId = opts.experienceId || opts.clientUrlId;
    var clientUrlId = opts.keyUrlId.replace(/\//g, ':');

    //var Db.OauthClients = Controllers.models.OauthClients;
    //var Db.ApiKeys = Controllers.models.ApiKeys;
    //var Db.Accounts = Controllers.models.Accounts;

    return Db.OauthClients.get(clientUrlId).then(function (client) {

      if (client) {
        return client;
      }

      if (opts.debug) {
        console.log('[Create OAuth3 Client]');
      }

      return OauthClients._todoGetGrootTodo(experienceId, opts).then(function (account) {
        return OauthClients.createHelper(account, clientUrlId);
      });
    }).then(function (oauthClient) {
      return OauthClients.createKeysHelper(opts, oauthClient, experienceId, clientUrlId, keyUrlId);
    });
  };

  OauthClients.checkOrigin = function (allowedUrls, origin, referer) {
    origin = (origin || '').replace(/\/^https?:\/\//, '').replace(/\/$/, '');
    referer = (referer || '').replace(/\/^https?:\/\//, '').replace(/\/$/, '');

    return allowedUrls.some(function (url) {
      url = url.replace(/\/^https?:\/\//, '').replace(/\/$/, '') + '#';

      // blar.com/foo/bar/baz/bee, blar.com/foo
      if (referer) {
        if (0 === (referer + '#').indexOf(url)) {
          return true;
        }
        return false;
      }

      if (origin) {
        if (0 === url.indexOf((origin + '#'))) {
          return true;
        }
        return false;
      }

      return false;
    });
  };

  OauthClients.loginHelper = function (config, id, secret, opts) {
    //console.log("DEBUG [oauthclient-microservice] login clientId '" + id + "' opts:");
    //console.log(opts);
    // authutils.hashsum('sha256', key)
    return OauthClients._getApiKeys(config, opts).then(function (apikey) {
      var err;

      if (!apikey) {
        return null;
      }

      if (apikey.insecure || ('server' in apikey && !apikey.server)) {
        if (!secret || secret === 'anonymous') {
          return apikey;
        } else {
          err = new Error("Incorrect Secret (insecure)");
          err.code = 'E_BAD_CLIENT_SECRET';
          return PromiseA.reject(err);
        }
      }
      else {
        if (!apikey.secret) {
          err = new Error("You provided a server app id, but no accompanying app secret.");
          err.code = 'E_NO_CLIENT_SECRET';
          return PromiseA.reject();
        }

        if (authutils.testSecret(apikey.salt, secret, apikey.shadow, apikey.hashtype)) {
          return apikey;
        }
        else {
          err = new Error("Incorrect Secret");
          err.code = 'E_INCORRECT_CLIENT_SECRET';
          return PromiseA.reject(err);
        }
      }
    }).then(function (apiKey) {
      if (!apiKey) {
        return null;
      }

      return Db.OauthClients.get(apiKey.oauthClientId).then(function (oauthClient) {
        // The extra '#' is to prevent foo.com.in from matching foo.com
        var allowedUrls = (oauthClient.urls || []).concat(apiKey.urls || []);
        var err;

        if (oauthClient.url) {
          allowedUrls.unshift(oauthClient.url);
        }

        if (apiKey.url) {
          allowedUrls.unshift(apiKey.url);
        }

        apiKey.oauthClient = oauthClient;

        if (opts.isDeviceClient) {
          return apiKey;
        }

        if (!(opts.origin || opts.referer)) {
          err = new Error("Incorrect clientUri [2]");
          err.code = 'E_INVALID_CLIENT_URI';
          console.log('DEBUG opts.origin error');
          console.log(err.stack);
          return PromiseA.reject(err);
        }

        // TODO define API for checking if this clientUri is allowed
        //console.log('DEBUG allowedUrls');
        //console.log(allowedUrls);
        //console.log(opts.origin, opts.referer);
        if (OauthClients.checkOrigin(allowedUrls, opts.origin, opts.referer)) {
          return apiKey;
        }

        err = new Error("Incorrect clientUri [3]");
        err.code = "E_INVALID_CLIENT_URI";
        return PromiseA.reject(err);
      });
    });
  };

  OauthClients.loginOrCreate = function (config, id, secret, opts) {
    console.log('DEBUG OauthClients.loginOrCreate');
    return OauthClients.loginHelper(config, id, secret, opts).then(function (result) {
      var err;

      if (result) {
        return result;
      }

      console.log('DEBUG createHelper(null, ' + opts.clientUri + ')');
      if (OauthClients.checkOrigin([opts.clientUri], opts.origin, opts.referer)) {
        return OauthClients.createHelper(null, opts.clientUri);
      }

      err = new Error("Incorrect clientUri [4]");
      err.code = "E_INVALID_CLIENT_URI";
      return PromiseA.reject(err);
    });
  };

  //
  // Controller
  //
  OauthClients.login = function (config, id, secret, opts) {
    console.log('DEBUG OauthClients.login');
    return OauthClients.loginHelper(config, id, secret, opts);
  };

  OauthClients.lookup = function (config, key, opts) {
    opts = opts || {};

    return Db.ApiKeys.find({ id: opts.id && key || authutils.hashsum('sha256', key) })
      .then(function (apiKey) {
        if (!apiKey) {
          return PromiseA.reject(new Error("Incorrect Api Key"));
        }

        return Db.OauthClients.get(apiKey.oauthClientId).then(function (oauthClient) {
          apiKey.oauthClient = oauthClient;
          return apiKey;
        });
      });
  };

  //
  // Helpers
  //
  function removeThing($things, id) {
    return $things.some(function ($thing, i) {
      if ($thing.id === id) {
        try {
          $thing.models.splice(i, 1);
          $thing.length -= 1;
        } catch(e) {
          console.error('[removeThing] $thing.models');
          console.log($thing);
        }

        return true;
      }
    });
  }

  function selectThing($things, id, keyName) {
    var $t;

    $things.forEach(function ($thing) {
      if (keyName) {
        if ($thing[keyName] === id) {
          $t = $thing;
        }
      } else if ($thing.id === id) {
        $t = $thing;
      }
    });

    return $t;
  }

  function updateThing(model, thing, updates) {
    var changed = false;

    Object.keys(updates).forEach(function (key) {
      if ('undefined' === typeof updates[key]) {
        return;
      }

      if (updates[key] !== thing[key]) {
        changed = true;
        thing[key] = updates[key];
        if ('undefined' === typeof thing[key]) {
          thing[key] = null;
        }
      }
    });

    if (changed) {
      return model.save(thing);
    }

    return PromiseA.resolve();
  }

  //
  // API Keys
  //
  OauthClients.createKeys = function (config, client, raw, manualOpts) {
    // Key lengths:
    // Facebook
    //   id         (6-byte) 15 digit int
    //   secret     (16-byte) 32 hex chars
    // Stripe
    //   id / secret (18-byte) 32/24 'pk_live_' + base62

    var keypair = {};
    var keynames = [
      'urls'      // allowed audiences
    , 'cnames'    // allowed servers (instead of ips)
    , 'priv'      // priv can be used to create pub
    , 'testers'
    , 'insecure'  // deprecated
    , 'server'    // replaces insecure
    , 'test'
    , 'desc'
    , 'expiresAt'
    // whether this key is for a user, an app, a device, etc
    //, 'iss'
    //, 'aud'
    //, 'sub'
    //, 'typ'
    //, 'scope'
    ];

    if (manualOpts && manualOpts.forceIds) {
      keynames.push('id');
      keynames.push('pub');
      keynames.push('secret');
      keynames.push('type');    // ?? device, user, app, etc
      keynames.push('subject'); // ?? allowed use, scope
    }

    keynames.forEach(function (k) {
      if (k in raw) {
        keypair[k] = raw[k];
      }
    });

    if (('server' in raw && !raw.server) || raw.insecure) {
      keypair.secret = 'anonymous';
    }

    function getId(byteLen, charLen) {
      var id;

      do {
        id = authutils.random(byteLen * 2, 'hex').replace(/^0+/g, '').replace(/[-_]+/g, '').substr(0, charLen);
      } while (id.length < charLen);

      return id;
    }

    function getSecret(byteLen, charLen) {
      var key;

      do {
        key = authutils.url64(byteLen * 2).replace(/^0+/g, '').replace(/[-_]+/g, '').substr(0, charLen);
      } while (key.length < charLen);

      return key;
    }

    // TODO JWT as key
    if (raw.test) {
      // TODO XXX allow user to specify test key while avoiding collision?
      keypair.key = ('TEST_ID_' + getId(16, 24));
      if (manualOpts && manualOpts.forceIds) {
        keypair.key = raw.key || keypair.key;
      }
      if (!keypair.secret) {
        keypair.secret = raw.secret || ('TEST_SK_' + getSecret(16, 24));
      }
    }
    else {
      keypair.key = 'ID__' + getId(16, 28);
      if (manualOpts && manualOpts.forceIds) {
        keypair.key = raw.key || keypair.key;
        keypair.secret = raw.secret || keypair.secret;
      }
      if (keypair.server && !keypair.secret) {
        keypair.secret = 'SK__' + getSecret(16, 28);
      }
    }

    keypair.id = authutils.hashsum('sha256', keypair.key);

    if (keypair.secret && 'anonymous' !== keypair.secret) {
      keypair.salt = authutils.url64(32);
      // TODO use pbkdf2-utils
      keypair.shadow = authutils.createShadow(keypair.secret, 'sha384', keypair.salt).shadow;
      keypair.hashtype = 'sha384';
    }
    // user needs to be able to view api secret
    //delete keypair.secret;

    keypair.oauthClientId = client.id;

    return Db.ApiKeys.create(keypair).then(function () {
      return keypair;
    });
  };

  OauthClients.getAllKeys = function (config, $client) {
    return $client.related('apikeys');
  };

  OauthClients.getKeys = function (config, client, keyId) {
    //var $keys = selectThing($client.related('apikeys'), keyId);
    //return $keys;
    return Db.ApiKeys.find({ id: keyId, clientId: client.id }).then(function (keys) {
      return keys;
    });
  };

  OauthClients.updateKeys = function (config, key, updates) {
    return updateThing(Db.ApiKeys, key, updates);
  };

  OauthClients.deleteKeys = function (config, $client, $key) {
    var key = $key.toJSON();

    removeThing($client.related('apikeys'), $key.id);

    return $key.destroy().then(function () {
      return key;
    });
  };

  //
  // Oauth Client Apps
  //
  OauthClients.create = function (config, account, raw, manualOpts) {
    var client = {};
    var keypairs;
    var ps = [];
    var validKeys;

    [ 'name'
    , 'desc'
    , 'urls'
    //, 'ips'
    , 'cnames'
    , 'logo'
    , 'live'
    , 'repo'
    , 'keywords'
    , 'insecure'
    , 'server'
    , 'status'
    , 'test'
    , 'primary_id'
    //, 'published'
    , 'testers'
    ].forEach(function (k) {
      if (k in raw) {
        client[k] = raw[k];
      }
    });

    client.accountId = account.id;
    if (account.iAmGroot) {
      client.root = true;
    }

    if (Array.isArray(raw.apiKeys)) {
      keypairs = raw.apiKeys;
    }
    keypairs = keypairs || [];

    validKeys = {
      'key': ''
    , 'secret': ''
    , 'test': true
    , 'insecure': true
    , 'server': true
    , 'desc': ''
    , 'urls': ['']
    //, 'ips': ['']
    , 'cnames': ['']
    , 'testers': []
    , 'expiresAt': new Date()
    };
    keypairs.forEach(function (keypair) {
      if ('key' in keypair || 'secret' in keypair) {
        if (!(manualOpts && manualOpts.forceIds)) {
          keypair.test = true;
        }
      }

      ps.push(validate(validKeys, keypair));
    });

    if (!client.accountId) {
      return PromiseA.reject(new Error("no accountId to associate"));
    }

    client.id = UUID.v4();
    // NOTE this secret is used for weak ciphering (reversible hash) for app scoping ids and such
    client.secret = crypto.randomBytes(264 / 8).toString('base64');

    function genKeys() {
      var keySets = [];

      // create test keys
      // create client keys
      if (client.test) {
        if (!client.insecure || ('server' in client && client.server)) {
          keySets.push({
            test: false
          , insecure: false
          , server: true
          , desc: "key for secure clients (ssl enabled web servers - node, ruby, python, etc)"
          });
        }

        keySets.push({
          test: false
        , insecure: true
        , server: false
        , desc: "key for insecure clients (browser, native apps, mobile apps)"
        });
      }

      if (!client.insecure || ('server' in client && client.server)) {
        keySets.push({
          test: true
        , insecure: false
        , server: true
        , desc: "test key for secure clients (ssl enabled web servers - node, ruby, python, etc)"
        });
      }

      keySets.push({
        test: true
      , insecure: true
      , server: false
      , desc: "test key for insecure clients (browser, native apps, mobile apps)"
      });

      return keySets;
    }

    return PromiseA.all(ps).then(function () {
      return Db.OauthClients.create(client).then(function (/*clientmeta*/) {
        //return Db.ApiKeys.find({ oauthclientId: client.id }).then(function (apikeys) {
          var ps = [];

          if (!keypairs.length) {
            keypairs = genKeys();
          }

          keypairs.forEach(function (pair) {
            ps.push(OauthClients.createKeys(config, client, pair, manualOpts));
          });

          return PromiseA.all(ps).then(function (apiKeys) {
            client.apiKeys = apiKeys;
            return client;
          });
        //});
      });
    });
  };

  OauthClients.get = function (config, account, clientId) {
    if (clientId) {
      return OauthClients.getOne(config, account, clientId);
    } else {
      return OauthClients.getAll(config, account);
    }
  };

  OauthClients.getOne = function (config, $account, clientId) {
    if (!clientId) {
      return null;
    }

    return $account.related('oauthclients').fetch({ withRelated: ['apikeys'] }).then(function () {
      return selectThing($account.related('oauthclients'), clientId);
    });
  };

  OauthClients.getAll = function (config, account) {
    return Db.OauthClients.find({ accountId: account.id }).then(function (oauthClients) {
      var promises = oauthClients.map(function (oauthClient) {
        return Db.ApiKeys.find({ oauthClientId: oauthClient.id }).then(function (apiKeys) {
          oauthClient.apiKeys = apiKeys;

          return oauthClient;
        });
      });

      return PromiseA.all(promises);
    });
  };


  OauthClients.update = function (config, client, updates) {
    return validate({
      'name': ''
    , 'desc': ''
    , 'urls': ['']
    //, 'ips': ['']
    , 'cnames': ['']
    , 'logo': ''
    , 'repo': ''
    , 'keywords': ['']
    , 'insecure': true
    , 'server': true
    , 'live': true
    , 'test': true
    //, 'primaryId'
    //, 'published'
    , 'testers': []
    /*
    , 'apikeys': [{
        'id': '' // allowed as an identifier, not mutable
      , 'urls': ['']
      //, 'ips': ['']
      , 'cnames': ['']
      , 'testers': []
      , 'desc': ''
      , 'expiresAt': new Date()
      }]
    */
    }, updates).then(function () {
      //var apikeys = updates.apikeys || [];
      var ps = [];

      delete updates.apiKeys;

      /*
      apikeys.forEach(function (pair) {
        var $pair = selectThing($client.related('apikeys'), pair.id);

        delete pair.id;
        ps.push(updateThing(Db.ApiKeys, $pair, pair));
      });
      */

      return PromiseA.all(ps).then(function () {
        return updateThing(Db.OauthClients, client, updates).then(function () {
          return client;
        });
      });
    });
  };

  OauthClients.delete = function (config, $account, $client) {
    return $account.load(['oauthclients']).then(function ($account) {
      return $client.load(['apikeys']).then(function ($client) {
        var client = $client.toJSON();
        var ps = [];

        removeThing($account.related('oauthclients'), $client.id);

        $client.related('apikeys').forEach(function ($key) {
          removeThing($client.related('apikeys'), $key.id);
          ps.push($key.destroy());
        });

        return PromiseA.all(ps).then(function () {
          return $client.destroy().then(function () {
            return client;
          });
        });
      });
    });
  };

  return OauthClients;
};
