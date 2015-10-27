module.exports.create = function (config, DB, LoginsCtrl) {
  'use strict';

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
    return LoginsCtrl.login({
      node: userId
    , type: nodeType
    , secret: proof.proof
    }).then(function () {
      return proof;
    }, function () {
      return LoginsCtrl.create({
        node: userId
      , type: nodeType
      , secret: proof.proof
      , salt: proof.salt
      , kdf: proof.kdf || 'pbkdf2'
      , algo: proof.algo
      , iter: proof.iter
      , bits: proof.bits
      }).then(function () {
        return proof;
      });
    });
  }).then(function (proof) {
    return {
      node: userId
    , type: nodeType
    , secret: proof.proof
    };
  });
};
