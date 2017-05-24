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

  OauthClients._failIfNotRegisterable = function (config, clientId, opts) {
    var err;

    if (!opts.clientAgreeTos) {
      err = new Error("Incorrect Api Key '" + clientId + "' (or missing client_agree_tos url)");
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
      //console.log('[DEBUG] [oauthclients.js]', opts);
      err = new Error("Incorrect clientUri");
      err.code = 'E_INVALID_CLIENT_URI';
      return PromiseA.reject(err);
    }
  };

  OauthClients._getApiKeys = function (config, opts) {
    var clientId = (opts.kid && OauthClients.getAutoId(opts.clientUri, opts.kid))
      || opts.id || opts.clientId || opts.clientUri;

    //console.log(new Error('[DEBUG] OauthClients._getApiKeys stack:').stack);
    return Db.ApiKeys.get(clientId).then(function (apiKey) {
      if (apiKey) {
        return apiKey;
      }

      return OauthClients._failIfNotRegisterable(config, clientId, opts);
    });
  };

  OauthClients.getKeyAndClientByPubKid = function (clientUri, kid) {
    // XXX TODO XXX
    // the same public / private key pair could be used by more than one client
    // do we want to allow that? or disallow that?
    var id = OauthClients.getAutoId(clientUri, kid);
    return Db.ApiKeys.get(id).then(function (apiKey) {
      if (!apiKey) {
        //console.log('DEBUG 1a', id);
        return null;
      }

      //console.log('DEBUG 1b');
      return Db.OauthClients.get(apiKey.oauthClientId).then(function (oauthClient) {
        //console.log('DEBUG 1c');
        apiKey.oauthClient = oauthClient;

        return apiKey;
      });
      //return OauthClients.getClientAndKeysById(apiKey.oauthClientId);
    });
  };

  OauthClients.getClientAndKeysByPubKid = function (clientUri, kid) {
    // XXX TODO XXX (see getKeyAndClientByPubKid)
    var id = OauthClients.getAutoId(clientUri, kid);
    return Db.ApiKeys.get(id).then(function (apiKey) {
      if (!apiKey) {
        return null;
      }

      return OauthClients.getClientAndKeysById(apiKey.oauthClientId);
    });
  };

  OauthClients.getClientAndKeysById = function (oauthClientId) {
    return Db.OauthClients.get(oauthClientId).then(function (oauthClient) {
      if (!oauthClient) {
        return null;
      }

      return Db.ApiKeys.find({ oauthClientId: oauthClientId }).then(function (apiKeys) {
        oauthClient.apiKeys = apiKeys || [];

        return oauthClient;
      });
    });
  };

  OauthClients.normalizeClientUri = function (clientUri) {
    // TODO lowercase just the hostname
    return clientUri.replace(/^https?:\/\//i, '').replace(/\/$/, '');
  };
  OauthClients.normalizeClientUriId = function (clientUri) {
    return OauthClients.normalizeClientUri(clientUri).replace(/\//g, ':');
  };

  // params = { clientUri, kid, pubKeyPem }
  OauthClients.registerApiKey = function (config, pubKeyPem, jwk, params) {
    //console.log('DEBUG step 1 get key', params.clientUri, params.kid || jwk.kid);
    return OauthClients.getKeyAndClientByPubKid(params.clientUri, params.kid || jwk.kid).then(function (apiKey) {
      //console.log('DEBUG step 2 finish get key');
      // TODO check against oauthclient options
      // (i.e. disallow auto-registration, only allow certain cnames)
      if (apiKey) {
        // Allow re-registration? dual registrations? (multiple issuers / azps?)
        //console.log('DEBUG step 3 return existing client');
        return apiKey;
      }

      var clientUriId = OauthClients.normalizeClientUriId(params.clientUri);
      return Db.OauthClients.get(clientUriId).then(function (oauthClient) {
        //console.log('DEBUG step 4 get client');
        if (!oauthClient) {
          //console.log('DEBUG step 5 create client');
          // TODO how to reap from the root account and give control to owner?
          return OauthClients._createHelper(null, clientUriId, params, false);
        }

        return oauthClient;
      }).then(function (oauthClient) {
        //console.log('DEBUG step 6 create key');
        //params.secret = crypto.randomBytes(16).toString('hex');
        return OauthClients.addApiKeysToClient(config, oauthClient, pubKeyPem, jwk, params).then(function (apiKey) {
          //console.log('DEBUG step 7 created key');
          //apiKey.secret = params.secret;
          //params.secret = undefined;
          apiKey.oauthClient = oauthClient;
          return apiKey;
        });
      });
    }).then(function (apiKey) {
      var secret = crypto.randomBytes(16).toString('hex');
      var oauthClient = apiKey.oauthClient;
      apiKey.oauthClient = undefined;

      //console.log('DEBUG step 8 rotateSecret');
      // if the client is re-registering, it must have lost it's secret
      // and therefore we must generate a new one
      return OauthClients.rotateSecret(apiKey, secret).then(function () {
        apiKey.client = {
          id: oauthClient.id
        , url: oauthClient.url
        , name: oauthClient.name
        , urls: oauthClient.urls
        };
        apiKey.secret = secret;

        apiKey.shadow = undefined;
        apiKey.hashtype = undefined;
        apiKey.salt = undefined;
        apiKey.alg = undefined;
        apiKey.bits = undefined;
        apiKey.pub = undefined;
        apiKey.type = undefined;
        apiKey.oauthClientId = undefined;

        //console.log('DEBUG step 9 return apiKey', apiKey);
        return apiKey;
      });
    });
  };

  OauthClients.getAutoId = function (clientUri, kid) {
    return OauthClients.normalizeClientUriId(clientUri) + ':' + kid;
  };
  OauthClients.addApiKeysToClient = function (config, oauthClient, publicKeyPem, jwk, params) {
    if ('boolean' !== typeof params.isDeviceClient) {
      return PromiseA.reject(new Error('[SANITY FAIL] isDeviceClient is not a property on params'));
    }

    // TODO should be used for database scoping
    //var experienceId = params.experienceId;
    var apiKey = OauthClients.genKeypair({
      id: OauthClients.getAutoId(params.clientUri, jwk.kid)
    , uri: params.clientUri
    , server: params.isDeviceClient
    , desc: 'Automatically registered client public key.'
    , jwk: jwk
    , secret: params.secret

    // TODO depracate
    , publicKeyPem: publicKeyPem // still needed in most places
    , kty: jwk.kty
    , alg: jwk.alg
    , bits: params.bits
    , mod: jwk.e || params.mod
    });
    apiKey.oauthClientId = oauthClient.id;
    apiKey.url = apiKey.uri;

    return Db.ApiKeys.create(apiKey).then(function () {
      return apiKey;
    });
  };

  OauthClients.rotateSecret = function (apiKey, secret) {
    apiKey.salt = authutils.url64(32);
    // TODO use pbkdf2-utils
    apiKey.shadow = authutils.createShadow(secret, 'sha256', apiKey.salt).shadow;
    apiKey.hashtype = 'sha256';

    return Db.ApiKeys.set(apiKey.id, apiKey).then(function () {
      return apiKey;
    });
  };

  OauthClients.genKeypair = function genKeypair(opts) {
    var crypto = require('crypto');
    var ursa = require('ursa');
    var bits = opts.bits || 1024;
    var mod = opts.mod || 65537; // seems to be the most common, not sure why
    var typ = opts.kty || 'rsa';
    var key;
    var pub = opts.publicKeyPem;
    var priv;
    var kid;
    var keydata;

    if (!pub) {
      key = ursa.generatePrivateKey(bits, mod);
      pub = key.toPublicPem().toString();
      priv = key.toPrivatePem().toString();
    }

    kid = opts.kid || opts.id || crypto.createHash('sha256').update(opts.uri + pub).digest('hex');

    keydata = {
      // id needs to be unique, but multiple sites could use the same private key
      id: kid

    , jwk: opts.jwk
    , server: opts.server || false
    , urls: opts.urls     // allowed audiences (i.e. the requesting client exampleapp.com and examplepartner.com)
    , cnames: opts.cnames // allowed servers (instead of ips)
    , desc: opts.desc

    // TODO deprecate
    , insecure: opts.insecure // deprecated (safe to remove here)
    , pub: pub
      // TODO priv should only be saved by the client, not in the db
      // (however, this could be the client as well)
    , priv: priv
    , bits: bits
    , type: typ
    , alg: opts.alg || 'RS256'
    };

    if (opts.secret) {
      keydata.salt = authutils.url64(32);
      // TODO use pbkdf2-utils
      keydata.shadow = authutils.createShadow(opts.secret, 'sha256', keydata.salt).shadow;
      keydata.hashtype = 'sha256';
    }
    else if (opts.server) {
      console.warn("server key created without secret... useless");
    }

    return keydata;
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
    var query = {};

    if (opts.debug) {
      console.log('[OAuth3 Client]', oauthClient.id, oauthClient);
    }

    if (keyUrlId) {
      query.url = keyUrlId;
    }
    if (oauthClient.id) {
      query.oauthClientId = oauthClient.id;
    }

    console.log("createKeysHelper query:");
    console.log(query);
    return Db.ApiKeys.find(query).then(function (apiKeys) {
      var apiKey;

      console.log('createKeysHelper apiKeys:');
      if (!apiKeys.length || !apiKeys.some(function (key) {
        return clientUrlId === key.id;
      })) {
        if (opts.debug) {
          console.log('[Create API Key], ' + oauthClient.id + ', ' + keyUrlId);
        }

        apiKey = OauthClients.genKeypair({
          id: experienceId
        , uri: experienceId
        , server: false // doesn't need secret
        , desc: 'Automatically provisioned client.'
        });
        apiKey.oauthClientId = oauthClient.id;
        apiKey.url = keyUrlId;

        return Db.ApiKeys.create(apiKey).then(function () {
          oauthClient.apiKeys = [apiKey];
          return oauthClient;
        });
      }

      // TODO not sure if this is exactly right (might be a subset of keys, is that what we want?)
      oauthClient.apiKeys = apiKeys;
      return oauthClient;
    });
  };

  // Note: this is the new method, the old one may not work
  OauthClients._createHelper = function (account, clientUrlId, opts, isRoot) {
    console.log("[DEBUG] _createHelper [a]");
    opts = opts || {};
    // owned by the system account until claimed by the uri owner
    if (!account) {
      account = {
        id: 'groot'
      };
    }
    var crypto = require('crypto');
    var client = {
      id: clientUrlId
    , url: clientUrlId
    , name: opts.name || clientUrlId
    , urls: [ 'https://' + clientUrlId ]
      // TODO if nothing uses cnames yet, it should be left empty (allow all)
      // because auto-registered client depends on shared private keys from potentially
      // different servers - i.e. api.walnut.example.com, walnut.example.com
    , cnames: [ clientUrlId ]

    , root: true === isRoot // the root client, not just a client attached to groot
    , accountId: account.id
    , secret: crypto.randomBytes(16).toString('hex')
    , dnsTxt: opts.dnsTxt
    };

    console.log("[DEBUG] _createHelper [b]");
    return Db.OauthClients.create(client.id, client).then(function () {
      console.log("[DEBUG] _createHelper [c]");
      return client;
    });
    //return PromiseA.reject(new Error("Not Implemented"));
  };

  OauthClients.getOrCreateRootClient = function (config, opts) {
    return OauthClients.getOrCreateClient(config, opts, true);
  };
  OauthClients.getOrCreateClient = function (config, opts, isRoot) {
    var keyUrlId = opts.keyUrlId;
    var experienceId = opts.experienceId || opts.clientUrlId;
    var clientUrlId = OauthClients.normalizeClientUriId(opts.keyUrlId);

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
        return OauthClients._createHelper(account, clientUrlId, { dnsText: opts.dnsTxt }, isRoot);
      });
    }).then(function (oauthClient) {
      return OauthClients.createKeysHelper(opts, oauthClient, experienceId, clientUrlId, keyUrlId);
    });
  };

  OauthClients.checkOrigin = function (allowedUrls, origin, referer, debug) {
    origin = OauthClients.normalizeClientUri(origin || '');
    referer = OauthClients.normalizeClientUri(referer || '');

    return allowedUrls.some(function (url) {
      url = OauthClients.normalizeClientUri(url) + '/';

      if (debug) {
        console.log('origin/', origin + '/');
        console.log('referer/', referer + '/');
        console.log('url/', url);
        console.log("0 === (referer + '/').indexOf(url)", 0 === (referer + '/').indexOf(url));
        console.log("0 === url.indexOf((origin + '/'))", 0 === url.indexOf((origin + '/')));
      }

      // blar.com/foo/bar/baz/bee/, blar.com/foo/
      if (referer) {
        if (0 === (referer + '/').indexOf(url)) {
          return true;
        }
        return false;
      }

      if (origin) {
        if (0 === url.indexOf((origin + '/'))) {
          return true;
        }
        return false;
      }

      return false;
    });
  };

  OauthClients.exists = function (config, id, opts) {
    opts = opts || {};
    opts.id = opts.id || id;
    return OauthClients._getApiKeys(config, opts).then(function (apikey) {
      if (!apikey) {
        return false;
      }

      if (opts.kid && apikey.id !== opts.kid) {
        return false;
      }

      return true;
    }, function () {
      return false;
    });
  };

  OauthClients.loginHelper = function (config, id, secret, opts) {
    //console.log("DEBUG [oauthclient-microservice] login clientId '" + id + "' opts:");
    //console.log(opts);
    // authutils.hashsum('sha256', key)
    opts = opts || {};
    opts.id = opts.id || id;
    if ('anonymous' === secret) {
      secret = undefined;
    }

    return OauthClients._getApiKeys(config, opts).then(function (apikey) {
      var err;

      if (!apikey) {
        return null;
      }
      else if (opts.skipAuth) {
        return apikey;
      }

      if (!apikey.server && !apikey.shadow) {
        if (!secret) {
          return apikey;
        } else {
          err = new Error("Incorrect Secret (insecure)");
          err.code = 'E_BAD_CLIENT_SECRET';
          return PromiseA.reject(err);
        }
      }
      else {
        if (!secret) {
          err = new Error("You provided a server app id, but no accompanying app secret.");
          err.code = 'E_NO_CLIENT_SECRET';
          return PromiseA.reject(err);
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

      function checkBrowserClientUri(oauthClient) {
        var allowedUrls = (oauthClient.urls || []).concat(apiKey.urls || []);
        var err;

        if (oauthClient.url) {
          allowedUrls.unshift(oauthClient.url);
        }

        if (apiKey.url) {
          allowedUrls.unshift(apiKey.url);
        }

        if (opts.isDeviceClient) {
          return apiKey;
        }

        if (!(opts.origin || opts.referer)) {
          err = new Error("Incorrect clientUri [2]");
          err.code = 'E_INVALID_CLIENT_URI';
          //console.log('[DEBUG] opts.origin error');
          //console.log(err.stack);
          return PromiseA.reject(err);
        }

        // TODO define API for checking if this clientUri is allowed
        //console.log('DEBUG allowedUrls');
        //console.log(allowedUrls);
        //console.log(opts.origin, opts.referer);
        if (OauthClients.checkOrigin(allowedUrls, opts.origin, opts.referer, false)) {
          // TODO use scmp to prevent timing attacks
          return apiKey;
        }

        /*
        console.log('DEBUG client details');
        console.log(opts.origin);
        console.log(opts.referer);
        console.log(allowedUrls);
        */
        err = new Error("Incorrect clientUri [3a]");
        err.code = "E_INVALID_CLIENT_URI";
        return PromiseA.reject(err);
      }

      function checkServerClientCnames(/*oauthClient*/) {
        // TODO add checking of ip against cnames
        // TODO use scmp to prevent timing attacks
        console.warn("[SECURITY WARNING] CNAME checking not yet implemented for client api keys");

        return apiKey;
      }

      return Db.OauthClients.get(apiKey.oauthClientId).then(function (oauthClient) {
        apiKey.oauthClient = oauthClient;

        if (opts.skipAuth) {
          return apiKey;
        }

        if (!secret) {
          return checkBrowserClientUri(oauthClient);
        }

        return checkServerClientCnames(oauthClient);
      });
    });
  };

  OauthClients.loginOrCreate = function (config, id, secret, opts) {
    return OauthClients.loginHelper(config, id, secret, opts).then(function (result) {
      var err;

      if (result) {
        return result;
      }

      if (OauthClients.checkOrigin([opts.clientUri], opts.origin, opts.referer)) {
        return OauthClients._createHelper(null, opts.clientUri, null, false);
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
    return OauthClients.loginHelper(config, id, secret, opts);
  };

  OauthClients.lookup = function (config, key, opts) {
    opts = opts || {};

    return Db.ApiKeys.find({ id: opts.id && key || authutils.hashsum('sha256', key) })
      .then(function (apiKeys) {
        var apiKey;
        var clientUri;

        console.log("[oauthclient-microservice/lib/oauthclients.js] [DEBUG] TODO DON'T AUTO-REGISTER CLIENT EVERY TIME");
        if (true || !apiKeys.length) {
          if (false && !opts.createClient) {
            return PromiseA.reject(new Error("Incorrect Api Key"));
          }
          else {
            // TODO check if this even looks like a uri
            clientUri = OauthClients.normalizeClientUri(key);
            return OauthClients.autoRegister(config, clientUri, opts);
          }
        }
        apiKey = apiKeys[0];

        return Db.OauthClients.get(apiKey.oauthClientId).then(function (oauthClient) {
          apiKey.oauthClient = oauthClient;
          return apiKey;
        });
      });
  };

  // TODO check DNS records for SRV and oauth3 tos directives ?
  // also switch check from oauth3.json to oauth3/directives.json
  // also, allow different apps on different ports?
  // TODO define how toses should be read
  // TODO should probably have an option to read from API source rather than oauth3.json
  function getTosAgreement(config, clientUri) {
    // var myTosUrl = 'https://' + (config.tosUrl || 'oauth3.org/tos/draft').replace(/^https?:\/\//i, '');
    var requestAsync = PromiseA.promisify(require('request').defaults({
      headers: {
        // TODO choose a more robust better UA (os, node version, etc)
        'User-Agent': 'OAuth3 Validation Agent'
      }
    }));
    var dns = PromiseA.promisifyAll(require('dns'));
    var dnsOpts = { ttl: true };
    var results = { a: null, aaaa: null, srv: null, txt: null };
    var url = require('url');
    var urlstr;
    var pathparts;
    var paths;
    var cloudSrv;
    var termsTxt;
    var directiveUrl;
    var servername;

    pathparts = clientUri.split('/');
    servername = pathparts.shift().split(':')[0];
    paths = pathparts.join('._');
    if (paths) {
      // example: oauth3.org -> _terms._cloud.oauth3.org
      // example: oauth3.org/ident/connect -> _terms._ident._connect._paths._cloud.oauth3.org
      paths = '_' + paths + '._paths';
    }

    cloudSrv = paths + '_cloud.' + servername;
    termsTxt = '_terms.' + paths + '_cloud.' + servername;
    directiveUrl = url.resolve('https://' + clientUri, '.well-known/oauth3/directives.json');

    results.srvQuery = cloudSrv;
    results.txtQuery = termsTxt;
    results.directiveUrl = directiveUrl;

    function upgradeAddress(v) {
      if (v.address) {
        return v;
      }
      // node <= v6 or so doesn't have ttl support, so we'll fudge it
      return {
        address: v
      , ttl: 60
      };
    }

    function ignoreError(e) {
      if ('ENODATA' !== e.code) {
        console.error('[getTosAgreement.ignoreError]');
        console.error(e);
      }
      // ignore
    }

    // Can't use dnsOpts until upgrading node to v7.4+
    return dns.resolve4Async(servername/*, dnsOpts*/).then(function (a) {
      results.a = a.map(upgradeAddress);
    }, ignoreError).then(function () {
      return dns.resolve6Async(servername/*, dnsOpts*/).then(function (aaaa) {
        results.aaaa = aaaa.map(upgradeAddress);
      }, ignoreError);
    }).then(function () {
      // For discovery of systems running on non-standard ports (not 443)
      return dns.resolveSrvAsync(cloudSrv).then(function (srv) {
        results.srv = srv;
      }, ignoreError);
    }).then(function () {
      return dns.resolveTxtAsync(termsTxt).then(function (txt) {
        results.txt = txt;
      }, ignoreError);
    }).then(function () {
      if (!results.a) {
        // TODO what is the attack vector for someone modifying their own hosts file?
        // ...they can get other app ids for their own account?
        console.warn("no A records found for " + servername + " ... might need to check on that");
        console.warn(results);
        return;
      }
      if (results.a.some(function (a) {
        // localhost, link-local, Private 24-bit block
        if (/^(127|169|10)\./.test(a.address)) {
          return true;
        }
        // Private 20-bit block
        if (/^172\./.test(a.address)) {
          if (a.address.split('.')[1] >= 16 && a.address.split('.')[1] <= 31) {
            return true;
          }
        }
        // Private 16-bit block
        if (/^(192\.168\.)/.test(a.address)) {
          return true;
        }
      })) {
        // don't attempt to make a request to (potentially) our own network
        results.private = true;
        return;
      }

      return requestAsync({
        url: directiveUrl
      }).then(function (resp) {
        if (200 === resp.statusCode) {
          try {
            results.terms = JSON.parse(resp.body).terms;
            return;
          } catch(e) {
            // try next
          }
        }

        urlstr = url.resolve('https://' + clientUri, '.well-known/oauth3.json');
        return requestAsync({
          url: urlstr
        }).then(function (resp) {
          if (200 === resp.statusCode) {
            try {
              results.terms = JSON.parse(resp.body).terms;
            } catch(e) {
            }
          }
        }, ignoreError);
      }, ignoreError);
    }).then(function () {
      // TODO implement actual checking
      if (Array.isArray(results.terms) && results.terms.some(function (tos) {
        // TODO handle jwt
        // TODO handle other TOSes
        return /^(https:\/\/)?oauth3.org\/tos\/draft$/.test(tos.url || tos);
      })) {
        results.agree = true;
        return results;
      }

      if (results.txt && results.txt.length) {
        // TODO check jwt
        results.agree = true;
        return results;
      }

      results.agree = false;
      return results;
    });
  }

  OauthClients.autoRegister = function (config, clientUri, opts) {
    console.log("[DEBUG] autoRegister [a]", clientUri);
    if ('undefined' === clientUri) {
      // TODO this should be checked on incoming
      return PromiseA.reject(new Error("Developer Error: 'client_uri' is the string literal 'undefined'."));
    }
    return getTosAgreement(config, clientUri).then(function (results) {
      if (results.agree) {
        return results;
      }

      var err;
      var myTosUrl = (config.tosUrl || 'oauth3.org/tos/draft');
      var msg;

      msg = "Autoregistration failed because no signed agreement compatible with '" + myTosUrl + "' could be found.";
      if (results.private) {
        msg += " A private address was detected (127.x.x.x, 169.x.x.x, 10.x.x.x, 172.[16-31].x.x, 192.168.x.x).";
        msg += " Please publish your signed agreement via DNS to 'TXT " + results.txtQuery + "'.";
      }
      else {
        msg += " Please publish your signed agreement in '" + results.directiveUrl + ".terms'.";
      }

      err = new Error(msg);
      err.code = "E_INVALID_TOS";
      return PromiseA.reject(err);
    }).then(function (validationResults) {
      var clientUriId = OauthClients.normalizeClientUriId(clientUri);
      // TODO what about when one site delegates to another?
      // example.net is a clientUriId for example.com?
      var opts2 = {
        name: opts.name
      , experienceId: clientUriId
      , clientUrlId: clientUriId
      , keyUrlId: clientUriId
      , dnsTxt: validationResults.txt
      };
      var isRoot = false;
      console.log("[DEBUG] autoRegister [c]");
      return OauthClients.getOrCreateClient(config, opts2, isRoot).then(function (oauthClient) {
        var apiKey = oauthClient.apiKeys.filter(function (k) { return k.id === clientUriId; })[0];

        apiKey.oauthClient = oauthClient;
        apiKey.oauthClient.dnsTxt = validationResults.txt;

        return apiKey;
      });
    });
  };

  //
  // Helpers
  //

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

  OauthClients.updateKeys = function (config, key, updates) {
    return updateThing(Db.ApiKeys, key, updates);
  };

  //
  // Oauth Client Apps
  //
  OauthClients.createManual = function (config, account, raw, manualOpts) {
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
    //if (account.iAmGroot) {
    //  client.root = true;
    //}
    client.root = manualOpts.root;

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

  OauthClients.getAll = function (config, account) {
    return Db.OauthClients.find({ accountId: account.id }).then(function (oauthClients) {
      var promises = oauthClients.map(function (oauthClient) {
        return Db.ApiKeys.find({ oauthClientId: oauthClient.id }).then(function (apiKeys) {
          oauthClient.apiKeys = apiKeys || [];
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

      return PromiseA.all(ps).then(function () {
        return updateThing(Db.OauthClients, client, updates).then(function () {
          return client;
        });
      });
    });
  };

  return OauthClients;
};
