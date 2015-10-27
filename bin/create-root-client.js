'use strict';

//var PromiseA = require('bluebird').Promise;
var config = require(process.argv[2] || '../config.test.js');
var apiKeys = require(process.argv[2] || '../config.test.keys.js');

require('../tests/setup-helper').create(config).then(function (stuff) {
  console.log('[Create Root OauthClient]');

  var OauthClients = stuff.ClientsCtrl;
  var account = {
    id: 'groot'
  , iAmGroot: true
  };

  return OauthClients.getAll(null, account).then(function (oauthClients) {
    if (oauthClients.length) {
      console.log('Found Existing');
      return oauthClients[0];
    }

    // TODO login as myself before creating root app
    return OauthClients.create(config, account, {
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
    }, { forceIds: true }).then(function (oauthClient) {
      console.log('Created New');
      return oauthClient;
    });
  }).then(function (client) {
    if (!client.apiKeys.length) {
      throw new Error('missing api keys');
    }

    client.apiKeys.forEach(function (key) {
      var title = (key.test && 'Development' || 'Production');
      title += ' ' + (key.insecure && 'Browser' || 'Server');
      title += ' Key:';
      console.log(title);
      console.log('    ' + key.key);
      if (key.secret && 'anonymous' !== key.secret) {
        console.log('    ' + key.secret);
      }
      console.log('');
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
