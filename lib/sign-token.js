'use strict';

var PromiseA = require('bluebird').Promise;

function cnMatch(pat, sub) {
  // example.com -> example.com
  // .example.com -> example.com
  // *.example.com -> example.com
  // foo.example.com -> foo.example.com
  var bare = pat.replace(/^(\*)?\./, '');
  // example.com -> .example.com
  var dot = '.' + bare;
  var index;

  // this is for tech support, testing, debugging only
  if ('*' === pat) {
    return true;
  }

  // matches a bare domain and all subdomains
  if (bare === sub) {
    return true;
  }

  // 'foo.example.com'.lastIndexOf('.example.com') + '.example.com'.length
  // === 'foo.example.com'.length;
  index = sub.lastIndexOf(dot);
  return sub.length === index + dot.length;
}

// TODO init needs to happen by master, before giving control to workers
module.exports.create = function (Db) {
  var result;
  var key;

  function loadKey(doCreate) {
    if (key) {
      return PromiseA.resolve(key);
    }

    function create() {
      if (!doCreate) {
        return PromiseA.reject(new Error("cert doesn't exist"));
      }

      var ursa = require('ursa');
      var key = ursa.generatePrivateKey(1024, 65537);
      var pem = key.toPrivatePem();

      // TODO Db.upsert sha-256 as id
      // TODO save should throw error if not saving
      return Db.save({ privateKey: pem.toString('ascii') }).then(function (val) {
        return val.privateKey;
      });
    }

    return Db.find(null, { orderBy: 'createdAt', orderByDesc: true, limit: 10 }).then(function (arr) {
      if (!arr.length) {
        return create();
        //return PromiseA.reject(new Error("no keys found"));
      }

      return arr[0].privateKey;
    }).then(function (privkeypem) {
      var ursa = require('ursa');
      return ursa.createPrivateKey(privkeypem/*, password, encoding*/);
    });
  }

  function loadOrCreate() {
    return loadKey(true).then(function () {
      return result;
    });
  }

  function sign(data) {
    return loadKey().then(function (key) {
      var jwt = PromiseA.promisifyAll(require('jsonwebtoken'));
      var privkeypem = key.toPrivatePem();
      // { cn: domainname }
      var tok = jwt.sign(data, privkeypem, { algorithm: 'RS256' });

      // jwt
      console.log('jwt.decode(tok)');
      console.log(jwt.decode(tok));

      console.log('tok');
      console.log(tok);

      return tok;
    });
  }

  function verify(domainname, token) {
    var cn = token.cn;

    if (!cnMatch(cn, domainname)) {
      return PromiseA.reject(new Error("invalid domain '" + domainname
        + "' for cn pattern '" + cn + "'"));
    }

    return PromiseA.resolve(true);
  }

  function verifyJwt(token) {
    var jwt = PromiseA.promisifyAll(require('jsonwebtoken'));
    return loadKey().then(function (key) {
      return jwt.verifyAsync(token, key.toPublicPem()/*, { ignoreExpiration: true }*/).then(function (decoded) {
        return decoded;
      });
    });
  }

  result = {
    sign: sign
  , init: loadOrCreate
  , loadKey: loadKey
  , verify: verify
  , verifyJwt: verifyJwt
  , cnMatch: cnMatch
  };

  return result; 
};

module.exports.cnMatch = cnMatch;
