'use strict';

function genKeypair(experienceId) {
  var crypto = require('crypto');
  var ursa = require('ursa');
  var bits = 1024;
  var mod = 65537; // seems to be the most common, not sure why
  var key = ursa.generatePrivateKey(bits, mod);

  return {
    id: crypto.createHash('sha256').update(experienceId + key.toPublicPem()).digest('hex')
  , pub: key.toPublicPem().toString()
  , priv: key.toPrivatePem().toString()
  , secret: crypto.randomBytes(16).toString('hex')
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
      client = {
        id: clientUrlId
      , url: clientUrlId
      , name: clientUrlId
      , root: account.iAmGroot
      , accountId: account.id
      , urls: ['https://' + clientUrlId]
      , cnames: [clientUrlId]
      };

      return OauthClients.create(client.id, client).then(function () {
        return client;
      });
    });
  }).then(function (oauthClient) {
    if (opts.debug) {
      console.log(oauthClient.id, oauthClient);
    }

    return ApiKeys.find({ oauthClientId: oauthClient.id, url: keyUrlId }).then(function (apiKeys) {
      var apiKey;

      if (!apiKeys.length) {
        if (opts.debug) {
          console.log('[Create API Key], ' + oauthClient.id + ', ' + keyUrlId);
        }

        apiKey = genKeypair(experienceId);
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
