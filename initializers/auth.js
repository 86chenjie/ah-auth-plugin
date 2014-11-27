
/*
 *Auth Initializer
*__Author__: Panjie SW <panjie@panjiesw.com>*
*__Project__: ah-auth-plugin*
*__Company__: Panjie SW*

Defines ``api.Auth``
*********************************************
 */
var Auth, AuthError, ImplementationError, Q, SignupError, UnauthorizedError, jwt, scrypt, uuid, _;

Q = require('q');

_ = require('underscore');

scrypt = require('scrypt');

jwt = require('jsonwebtoken');

uuid = require('node-uuid');

AuthError = function(message, code) {
  this.name = "AuthError";
  this.message = message;
  this.code = code;
  this.status = 500;
};

AuthError.prototype = new Error();

AuthError.prototype.constructor = AuthError;

ImplementationError = function(message, code) {
  this.name = "ImplementationError";
  this.message = message;
  this.code = code;
  this.status = 500;
};

ImplementationError.prototype = new Error();

ImplementationError.prototype.constructor = ImplementationError;

SignupError = function(message, code) {
  this.name = "SignupError";
  this.message = message;
  this.code = code;
  this.status = 400;
};

SignupError.prototype = new Error();

SignupError.prototype.constructor = SignupError;

UnauthorizedError = function(message, code) {
  this.name = "UnauthorizedError";
  this.message = message;
  this.code = code;
  this.status = 401;
};

UnauthorizedError.prototype = new Error();

UnauthorizedError.prototype.constructor = UnauthorizedError;

Auth = function(api, next) {
  var config, encodePassword, matchPassword, signIn, signPayload, signUp, verifyToken, _encodePassword, _hninvoke, _matchPassword;
  config = api.config.auth;
  _hninvoke = function(object, name) {
    var args, callback, deferred, result;
    deferred = Q.defer();
    callback = function(err, result) {
      if (err) {
        return deferred.reject(err);
      } else {
        return deferred.resolve(result);
      }
    };
    args = [].slice.call(arguments, 2) || [];
    args.push(callback);
    result = object[name].apply(object, args);
    if (Q.isPromiseAlike(result)) {
      return result;
    } else {
      return deferred.promise;
    }
  };
  _encodePassword = {
    scrypt: function(password) {
      return Q.ninvoke(scrypt, 'passwordHash', password, config.scrypt.maxtime);
    }
  };
  encodePassword = function(password, callback) {
    var promise;
    if (api.AuthImpl && api.AuthImpl.encodePassword) {
      promise = _hninvoke(api.AuthImpl, 'encodePassword', password);
    } else {
      promise = _hninvoke(_encodePassword, 'scrypt', password);
    }
    promise.nodeify(callback);
    return promise;
  };
  _matchPassword = {
    scrypt: function(passwordHash, password) {
      var deferred;
      deferred = Q.defer();
      scrypt.verifyHash(passwordHash, password, function(err, result) {
        if (err) {
          return deferred.reject(err);
        } else {
          return deferred.resolve(result);
        }
      });
      return deferred.promise;
    }
  };
  matchPassword = function(passwordHash, password, callback) {
    var deferred;
    deferred = Q.defer();
    if (api.AuthImpl && api.AuthImpl.encodePassword) {
      if (!api.AuthImpl.matchPassword) {
        deferred.reject(new ImplementationError("No 'api.AuthImpl.matchPassword' implementation"));
      } else {
        _hninvoke(api.AuthImpl, 'matchPassword', passwordHash, password).then(function(result) {
          return deferred.resolve(result);
        })["catch"](function(error) {
          return deferred.reject(error);
        });
      }
    } else {
      _matchPassword['scrypt'](passwordHash, password).then(function(result) {
        return deferred.resolve(result);
      })["catch"](function(err) {
        var error;
        error = null;
        if (err.err_message) {
          error = new UnauthorizedError('Invalid credentials', 'incorrect_password');
        } else {
          error = new AuthError(err.message, 'server_error');
        }
        return deferred.reject(error);
      });
    }
    return deferred.promise.nodeify(callback);
  };
  signPayload = function(payload, expire) {
    if (expire == null) {
      expire = config.jwt.expire;
    }
    return jwt.sign(payload, config.jwt.secret, {
      expiresInMinutes: expire,
      algorithm: config.jwt.algorithm
    });
  };
  verifyToken = function(token, options, callback) {
    return Q.ninvoke(jwt, 'verify', token, config.jwt.secret, options).nodeify(callback);
  };
  signUp = function(userData, passwordField, needVerify, callback) {
    var deferred;
    deferred = Q.defer();
    userData.verified = !needVerify;
    encodePassword(userData[passwordField]).then(function(passwordHash) {
      var _uuid;
      userData[passwordField] = passwordHash;
      if (!(api.AuthImpl && api.AuthImpl.signUp)) {
        throw new ImplementationError("no 'api.AuthImpl.signUp' implementation.");
      }
      _uuid = null;
      if (config.enableVerification && needVerify) {
        _uuid = uuid.v4();
      }
      return _hninvoke(api.AuthImpl, 'signUp', userData, _uuid);
    }).then(function(data) {
      var options;
      if (!data.user) {
        throw new ImplementationError("no 'user' field in returned hash of 'api.AuthImpl.signUp'");
      }
      if (config.enableVerification) {
        if (!data.uuid) {
          throw new ImplementationError("Verification is enabled but no 'uuid' field in returned hash of 'api.AuthImpl.signUp'.");
        }
        if (!api.Mailer) {
          throw new Error("You need to install ah-nodemailer-plugin to be able to send verification mail.");
        }
        options = {
          mail: {
            to: data.user.email
          },
          locals: {
            uuid: data.uuid
          }
        };
        if (data.options && data.options.template) {
          options.template = data.options.template;
        } else {
          options.template = 'welcome';
        }
        if (data.options) {
          _.defaults(options.mail, data.options.mail);
          _.defaults(options.locals, data.options.locals);
        }
        return api.Mailer.send(options);
      } else {
        return Q(data);
      }
    }).then(function(responseOrData) {
      return deferred.resolve(true);
    })["catch"](function(error) {
      return deferred.reject(error);
    });
    return deferred.promise.nodeify(callback);
  };
  signIn = function(login, password, callback) {
    var deferred;
    deferred = Q.defer();
    if (!(api.AuthImpl && api.AuthImpl.findUser && api.AuthImpl.jwtPayload)) {
      deferred.reject(new ImplementationError("no 'api.AuthImpl.findUser' and or 'api.AuthImpl.jwtPayload' implementation.", 'signin_impl_error'));
    }
    _hninvoke(api.AuthImpl, 'findUser', login).then(function(user) {
      return Q.all([Q(user), matchPassword(user.password, password)]);
    }).spread(function(user, match) {
      if (match) {
        return _hninvoke(api.AuthImpl, 'jwtPayload', user);
      }
      throw new UnauthorizedError('Invalid credentials', 'invalid_credentials');
    }).then(function(data) {
      var signedPayload;
      signedPayload = signPayload(data.payload, data.expire);
      return deferred.resolve(signedPayload);
    })["catch"](function(err) {
      return deferred.reject(err);
    });
    return deferred.promise.nodeify(callback);
  };
  api.Auth = {
    encodePassword: encodePassword,
    matchPassword: matchPassword,
    signPayload: signPayload,
    verifyToken: verifyToken,
    signUp: signUp,
    signIn: signIn,
    authenticate: signIn,
    AuthError: AuthError,
    ImplementationError: ImplementationError,
    SignupError: SignupError,
    UnauthorizedError: UnauthorizedError,
    errors: {
      user_already_exist: function(message) {
        if (message == null) {
          message = 'User already exist';
        }
        return new SignupError(message, 'user_already_exist');
      },
      invalid_credentials: function(message) {
        if (message == null) {
          message = 'Invalid credentials';
        }
        return new UnauthorizedError(message, 'invalid_credentials');
      }
    }
  };
  return next();
};

exports.auth = Auth;
