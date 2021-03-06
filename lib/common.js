'use strict';

module.exports.rejectableRequest = function rejectableRequest(req, res, promise, msg) {
  return promise.error(function (err) {
    res.error(err);
  }).catch(function (err) {
    console.error('[ERROR] \'' + msg + '\'');
    console.error(err.message);
    console.error(err.stack);

    res.error(err);
  });
};

module.exports.promisableRequest =
module.exports.promiseRequest = function promiseRequest(req, res, promise, msg) {
  return promise.then(function (result) {
    if (result._cache) {
      res.setHeader('Cache-Control', 'public, max-age=' + (result._cache / 1000));
      res.setHeader('Expires', new Date(Date.now() + result._cache).toUTCString());
    }
    if (result._mime) {
      res.setHeader('Content-Type', result._mime);
    }
    if (result._value) {
      result = result._value;
    }
    res.send(result);
  }).error(function (err) {
    res.error(err);
  }).catch(function (err) {
    console.error('[ERROR] \'' + msg + '\'');
    console.error(err.message);
    console.error(err.stack);

    res.error(err);
  });
};
