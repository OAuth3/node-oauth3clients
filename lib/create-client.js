'use strict';

function genKeypair(opts) {
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
}

module.exports.genKeypair = genKeypair;
module.exports.getOrCreateClient = function (Controllers, opts) {
  var keyUrlId = opts.keyUrlId;
  var experienceId = opts.experienceId || opts.clientUrlId;
  var clientUrlId = opts.keyUrlId.replace(/\//g, ':');

  var OauthClients = Controllers.models.OauthClients;
  var ApiKeys = Controllers.models.ApiKeys;
  var Accounts = Controllers.models.Accounts;

  return OauthClients.get(clientUrlId).then(function (client) {

    if (client) {
      return client;
    }

    if (opts.debug) {
      console.log('[Create OAuth3 Client]');
    }

    return Accounts.get('groot').then(function (account) {
      if (account) {
        return account;
      }

      account = { id: 'groot', iAmGroot: true };

      if (opts.debug) {
        console.log('[Create User Profile]', experienceId);
      }

      return Accounts.create(account.id, account).then(function () {
        return account;
      });
    }).then(function (account) {
      var crypto = require('crypto');

      client = {
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
    });
  }).then(function (oauthClient) {
    if (opts.debug) {
      console.log('[OAuth3 Client]', oauthClient.id, oauthClient);
    }

    return ApiKeys.find({ oauthClientId: oauthClient.id, url: keyUrlId }).then(function (apiKeys) {
      var apiKey;

      if (!apiKeys.length) {
        if (opts.debug) {
          console.log('[Create API Key], ' + oauthClient.id + ', ' + keyUrlId);
        }

        apiKey = genKeypair({
          id: experienceId
        , uri: experienceId
        , server: false
        , insecure: true // deprecated (safe to remove here)
        , desc: 'Automatically provisioned client.'
        });
        apiKey.oauthClientId = oauthClient.id;
        apiKey.url = keyUrlId;

        return ApiKeys.create(apiKey).then(function () {
          oauthClient.apiKeys = [apiKey];
          return oauthClient;
        });
      }

      oauthClient.apiKeys = apiKeys;
      return oauthClient;
    });
  });
};
