module.exports.create = function (config, DB) {
  'use strict';

  var ContactNodes = require('../../lib/contact-nodes').create(config, DB);
  var CodesStore = require('authcodes').create(DB.Codes);
  var LoginStore = require('../../authentication-microservice/lib/logins').create({}, CodesStore, DB);
  //var Logins = require('../../lib/lds-logins').createController(config, LoginStore, DB, ContactNodes);
  var getProofOfSecret = require('../../authentication-microservice/lib/pbkdf2-utils').getProofOfSecret;
  var sha256 = require('../../authentication-microservice/lib/pbkdf2-utils').sha256;

  var kdfMeta = {
    salt: null // assigned below
  , kdf: 'pbkdf2'
  , algo: 'sha256'
  , iter: 678
  };
  var userId = 'coolaj86@gmail.com';
  var nodeType = 'email';
  var salt;

  // success because it's inherently recoverable
  salt = sha256(new Buffer(userId).toString('hex') + config.appId);
  return getProofOfSecret(salt, 'MY_SPECIAL_SECRET', kdfMeta.iter).then(function (proof) {
    console.log('proof.proof', proof.proof, proof.proof.length);
    return LoginStore.create({
      node: userId
    , type: nodeType
    , secret: proof.proof
    , salt: proof.salt
    , kdf: proof.kdf || 'pbkdf2'
    , algo: proof.algo
    , iter: proof.iter
    }).then(function (/*login*/) {
      return {
        node: userId
      , type: nodeType
      , secret: proof.proof
      , Logins: LoginStore
      };
    });
  });
};
