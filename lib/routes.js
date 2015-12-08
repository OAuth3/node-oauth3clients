'use strict';

module.exports.createView = function (config, Db) {
  var OauthClients = module.exports.createController(config, Db);

  //
  // RESTful OAuth
  //
  OauthClients.restful = {};

  //
  // API Keys
  //
  OauthClients.restful.createKeys = function (req, res) {
    var config = req.config;
    var $client = req.$client;
    var keys = req.body;

    OauthClients.createKeys(config, $client, keys).then(function ($key) {
      res.json($key.toJSON());
    }).error(function (err) {
      res.error(err);
    }).catch(function (err) {
      console.error('[Error] CREATE Api Keys');
      console.error(err);
      res.error(err);
    });
  };

  OauthClients.restful.getAllKeys = function (req, res) {
    var $keys = req.$keys;

    res.json($keys.toJSON());
  };

  OauthClients.restful.getKeys = function (req, res) {
    var $key = req.$key;

    res.json($key.toJSON());
  };

  OauthClients.restful.updateKeys = function (req, res) {
    var config = req.config;
    var updates = req.body;
    var $key = req.$key;

    OauthClients.updateKeys(config, $key, updates).then(function () {
      res.json({ success: true });
    }).error(function (err) {
      res.error(err);
    }).catch(function (err) {
      console.error('[Error] UPDATE API Keys');
      console.error(err);
      res.error(err);
    });
  };

  OauthClients.restful.deleteKeys = function (req, res) {
    var config = req.config;
    var $client = req.$client;
    var $key = req.$key;

    OauthClients.deleteKeys(config, $client, $key).then(function (key) {
      res.json(key);
    }).error(function (err) {
      res.error(err);
    }).catch(function (err) {
      console.error('[Error] DELETE API Keys');
      console.error(err);
      res.error(err);
    });
  };


  //
  // OAuth Client Apps
  //
  OauthClients.restful.create = function (req, res) {
    var config = req.config;
    var $account = req.$account;
    var client = req.body;

    OauthClients.create(config, $account, client).then(function ($client) {
      res.json($client.toJSON());
    }).error(function (err) {
      res.error(err);
    }).catch(function (err) {
      console.error('[Error] CREATE OAUTH CLIENT');
      console.error(err);
      res.error(err);
    });
  };

  OauthClients.restful.getAll = function (req, res) {
    var clients = req.clients;
    // TODO create a test app for everyone when they access their list?
    /*
    var demoApps = [
      { name: "Test App"
      , url: "https://local.ldsconnect.org:4443"
      , logo: "https://dropsha.re/files/pink-emu-16/ldsconnect-app-256.png"
      , token: "09177b4c-2052-test-b672-5eda1321729e"
        // 746913342088510 for facebook
      , id: "55c7-test-bd03"
        // ad539732cbfbd60169f32336e257b37c for testing facebook
      , secret: "6b2fc4f5-test-8126-64e0-b9aa0ce9a50d"
        // http://local.foobar3000.com:4080 for testing facebook)
      , callback: "https://local.ldsconnect.org:4443"
      , description: "Use the username 'dumbledore' with password 'secret' to log in to the developer sandbox account. The 'Howarts Magical Realm' Area includes the 'Bettendorf' stake and 4 wards."
      , comments: "You can use this right away to start testing your application"
      , live: false
      , test: true
      }
    ];
    */

    //res.send({ clients: demoApps.concat($clients.toJSON()) });
    res.send({ clients: clients.filter(function (client) {
      // TODO filter out dev clients
      return !client.root;
    }) });
  };

  OauthClients.restful.getOne = function (req, res) {
    var $client = req.$client;

    res.json($client.toJSON());
  };

  OauthClients.restful.update = function (req, res) {
    var config = req.config;
    var $client = req.$client;
    var client = req.body;

    OauthClients.update(config, $client, client).then(function ($client) {
      res.json($client.toJSON());
    }).error(function (err) {
      res.error(err);
    }).catch(function (err) {
      console.error('[Error] UPDATE OAUTH CLIENT');
      console.error(err);
      res.error(err);
    });
  };

  OauthClients.restful.delete = function (req, res) {
    var config = req.config;
    var $account = req.$account;
    var $client = req.$client;

    OauthClients.delete(config, $account, $client).then(function (client) {
      res.json(client);
    }).error(function (err) {
      res.error(err);
    }).catch(function (err) {
      console.error('[Error] DELETE OAUTH CLIENT');
      console.error(err);
      res.error(err);
    });
  };

  return OauthClients;
};
