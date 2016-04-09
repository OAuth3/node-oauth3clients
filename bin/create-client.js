'use strict';

var config = {
  ipcKey: require('crypto').randomBytes(16).toString('hex')
, sqlite3Sock: '/tmp/' + require('crypto').randomBytes(16).toString('hex') + '.sqlite3'
};

var clientUrlId = process.argv[2];
var keyUrlId = process.argv[3] || '';
var experienceId = keyUrlId.replace(/\//g, ':');

if (!clientUrlId || !keyUrlId) {
  console.log("Usage:   node bin/create-client <client-url-id> <api-key-url>");
  console.log("Example: node bin/create-client 'example.com' 'examplepartner.com/connect'");
  return;
}

var getControllers = require('oauthcommon/example-oauthmodels').create(config).getControllers;

getControllers(experienceId).then(function (Controllers) {

  require('../lib/oauthclients').createController({}, Controllers.models).getOrCreateClient({}, {
    debug: true
  , clientUrlId: clientUrlId
  , keyUrlId: keyUrlId
  , experienceId: experienceId
  }).then(function (client) {
    client.apiKeys.forEach(function (key) {
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
