'use strict';

var clientUrlId = process.argv[2];
var keyUrlId = process.argv[3] || '';
var experienceId = keyUrlId.replace(/\//g, ':');
var config = {
  ipcKey: require('crypto').randomBytes(16).toString('hex')
, sqlite3Sock: '/tmp/' + require('crypto').randomBytes(16).toString('hex') + '.sqlite3'
};

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

if (!clientUrlId || !keyUrlId) {
  console.log("Usage:   node bin/create-client <client-url-id> <api-key-url>");
  console.log("Example: node bin/create-client 'example.com' 'examplepartner.com/connect'");
  return;
}

var getControllers = require('oauthcommon/example-oauthmodels').create(config).getControllers;

getControllers(experienceId).then(function (Controllers) {
  //var models = Controllers.models;
  var OauthClients = Controllers.models.OauthClients;
  var ApiKeys = Controllers.models.ApiKeys;
  var Accounts = Controllers.models.Accounts;

  return Accounts.get('groot').then(function (account) {
    if (account) {
      return account;
    }

    account = { id: 'groot', iAmGroot: true };

    console.log('[Create User Profile]', experienceId);
    return Accounts.create(account.id, account).then(function () {
      return account;
    });
  }).then(function (account) {

    return OauthClients.get(clientUrlId).then(function (client) {

      if (client) {
        return client;
      }
      console.log('[Create OAuth3 Client]');

      /*
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
          ]

          name: "Daplie Connect"
        , desc: "Internal, root-level application for Daplie Connect"
        , urls: [
            "https://daplie.com"
          , "https://oauth3.org"
          , "https://local.daplie.com"
          , "https://local.oauth3.org"
          , "https://beta.daplie.com"
          , "https://beta.oauth3.org"
          ]
        // seeing as how ips are ephemeral in a federated model, I don't think they're valid to check againsnt
        //, ips: ["67.166.110.237", "66.172.10.146", "127.0.0.1"]
        // any ip from any A records returned by these domains will do
        , cnames: ["servers.oauth3.org", "servers.daplie.com"]
        , logo: "https://daplie.com/connect/images/logo-120px.png"
        , live: true
        , repo: "https://github.com/OAuth3/oauth3.org-backend"
        , keywords: ["oauth3.org", "api", "root"]
        , apiKeys: apiKeys
      */
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
    }).then(function (oauthClient) {
      console.log(oauthClient.id, oauthClient);
      return ApiKeys.find({ oauthClientId: oauthClient.id, url: keyUrlId }).then(function (apiKeys) {
        var apiKey;

        if (!apiKeys.length) {
          console.log('[Create API Key], ' + oauthClient.id + ', ' + keyUrlId);

          apiKey = genKeypair(experienceId);
          apiKey.oauthClientId = oauthClient.id;
          apiKey.url = keyUrlId;

          return ApiKeys.create(apiKey).then(function () {
            return [apiKey];
          });
        }

        return apiKeys;
      });
    }).then(function (apiKeys) {
      apiKeys.forEach(function (key) {
        var title = (key.test && 'Development' || 'Production');

        title += ' ' + (key.server && 'Server' || 'Browser');
        title += ' Key:';
        console.log(title);
        //console.log('    ' + key.pub.replace(/\s+/g, ''));
        console.log('    ' + key.pub.toString().replace(/\s+/g, ''));
        if (key.secret && 'anonymous' !== key.secret) {
          console.log('    ' + key.secret);
        }
        console.log('');
      });
    });
  });
}, function (err) {
  console.error('[ERROR]');
  console.error(err);
  console.error(err.stack);
  console.error(err.message);
});

process.on('unhandledRejection', function (err) {
  console.error("[unhandledRejection]");
  console.error(err);
  console.error(err.stack);
  console.error(err.message);

  throw err;
});
