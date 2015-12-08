module.exports.createRouter = function (app, config, Db) {
  var OauthClients = module.exports.createView(config, Db);

  function requireClient(req, res, next) {
    var $account = req.$account;
    var clientId = req.params.clientId;
    var p;

    if (clientId) {
      p = OauthClients.getOne(null, $account, clientId).then(function ($client) {
        req.$client = $client;

        if (!$client) {
          return PromiseA.reject(new Error("did not find that client"));
        }

        next();
      });
    } else {
      p = OauthClients.getAll(null, $account).then(function ($clients) {
        req.$clients = $clients;

        if (!$clients) {
          return PromiseA.reject(new Error("did not find clients associated with this account"));
        }

        next();
      });
    }

    return p.error(function (err) {
      res.error(err);
    }).catch(function (err) {
      console.error('[ERROR] requireClient');
      console.error(err);
      res.error(err);
    });
  }

  /*
  function requireKeys(req, res, next) {
    var $client = req.$client
      , keyId = req.params.keyId
      , p
      ;

    if (keyId) {
      p = OauthClients.getKeys(null, $client, keyId).then(function ($key) {
        req.$key = $key;

        if (!$key) {
          return PromiseA.reject(new Error("keys not found by that id"));
        }

        next();
      });
    } else {
      p = OauthClients.getAllKeys(null, $client).then(function ($keys) {
        req.$keys = $keys;

        if (!$keys) {
          return PromiseA.reject(new Error("keys not found by that id"));
        }

        next();
      });
    }
    
    return p.error(function (err) {
      res.error(err);
    }).catch(function (err) {
      console.error('ERROR requireClient');
      console.error(err);
      res.error(err);
    });
  }
  */

  function requireAccount(req, res, next) {
    var accountId = req.params.accountId;

    if (!req.oauth3) {
      res.error({
        code: "E_SANITY_FAIL"
      , message: "did not pass through the oauth3 handler"
      });
      return;
    }

    if (!req.oauth3.$client) {
      res.error({
        code: "E_INVALID_APP_ID"
      , message: "no app was found by that app id"
      });
      return;
    }

    accountId = decipher(accountId, req.oauth3.$client.get('secret'));

    if (!accountId) {
      res.error({
        code: "E_INVALID_ACCOUNT_ID"
      , message: "no account was found by that app id"
      });
      return;
    }

    if (!req.oauth3.accounts$) {
      res.error({
        code: "E_INVALID_ACCOUNT_ID"
      , message: "no accounts exist by that access token"
      });
    }

    req.oauth3.accounts$.forEach(function ($account) {
      if (accountId === $account.id) {
        req.$account = $account;
      }
    });

    if (!req.$account) {
      res.error({
        code: "E_INVALID_ACCOUNT_ID"
      , message: "that account is not accessible from this token"
      });
      return;
    }

    next();
  }

  function requireVerifiedAccount() {
    // TODO check config.verificationStaleTime
    return function (req, res, next) {
      var staleTime = 3 * 30 * 24 * 60 * 60 * 1000;
      var emailVerifiedAt = req.$account.get('public').emailVerifiedAt;
      var phoneVerifiedAt = req.$account.get('public').phoneVerifiedAt;
      var fresh = true;

      fresh = fresh && (Date.now() - new Date(emailVerifiedAt).valueOf()) < staleTime;
      fresh = fresh && (Date.now() - new Date(phoneVerifiedAt).valueOf()) < staleTime;

      if (!fresh) {
        console.error('req.$account.toJSON()');
        console.error(req.$account.toJSON());
        res.error(new Error(
          "For security it is required that you periodically verify your contact details."
        + " Please verify your contact details now."
        ));
        return;
      }

      next();
    };
  }

  // 
  // ROUTES
  //
  OauthClients.route = function (rest) {
    //rest.get('/me/clients', requireClient, OauthClients.restful.getAll);
    //rest.post('/me/clients', requireVerifiedAccount(['email', 'phone']), OauthClients.restful.create);

    /*
    rest.get('/me/clients/:clientId', requireClient, OauthClients.restful.getOne);
    rest.post('/me/clients/:clientId', requireVerifiedAccount(['email', 'phone']), requireClient, OauthClients.restful.update);
    */

    rest.get(
      '/accounts/:accountId/clients'
    , requireAccount
    , requireClient
    , OauthClients.restful.getAll
    );
    rest.get(
      '/accounts/:accountId/clients/:clientId'
    , requireAccount
    , requireClient
    , OauthClients.restful.getOne
    );
    rest.post(
      '/accounts/:accountId/clients'
    , requireAccount
    , requireVerifiedAccount(['email', 'phone'])
    , OauthClients.restful.create
    );
    rest.post(
      '/accounts/:accountId/clients/:clientId'
    , requireAccount
    , requireVerifiedAccount(['email', 'phone'])
    , requireClient
    , OauthClients.restful.update
    );
    rest.delete(
      '/accounts/:accountId/clients/:clientId'
    , requireAccount
    , requireClient
    , OauthClients.restful.delete
    );

    //rest.post('/me/clients/:clientId/keys', requireClient, OauthClients.restful.createKeys);
    /*
    rest.get('/me/clients/:clientId/keys', requireClient, requireKeys, OauthClients.restful.getAllKeys);
    rest.get('/me/clients/:clientId/keys/:keyId', requireClient, requireKeys, OauthClients.restful.getKeys);
    rest.post('/me/clients/:clientId/keys/:keyId', requireClient, requireKeys, OauthClients.restful.updateKeys);
    rest.delete('/me/clients/:clientId/keys/:keyId', requireClient, requireKeys, OauthClients.restful.deleteKeys);
    */

    /*
    rest.post('/me/clients', OauthClients.restful.create);
    rest.get('/me/clients', requireClient, OauthClients.restful.getAll);
    rest.get('/me/clients/:clientId', requireClient, OauthClients.restful.getOne);
    rest.post('/me/clients/:clientId', requireClient, OauthClients.restful.update);
    rest.delete('/me/clients/:clientId', requireClient, OauthClients.restful.delete);

    rest.post('/me/clients/:clientId/keys', requireClient, OauthClients.restful.createKeys);
    rest.get('/me/clients/:clientId/keys', requireClient, requireKeys, OauthClients.restful.getAllKeys);
    rest.get('/me/clients/:clientId/keys/:keyId', requireClient, requireKeys, OauthClients.restful.getKeys);
    rest.post('/me/clients/:clientId/keys/:keyId', requireClient, requireKeys, OauthClients.restful.updateKeys);
    rest.delete('/me/clients/:clientId/keys/:keyId', requireClient, requireKeys, OauthClients.restful.deleteKeys);    */
  };
  OauthClients.OauthClients = OauthClients;

  return OauthClients;
};
