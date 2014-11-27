
/*
 *Authentication Actions
*__Author__: Panjie SW <panjie@panjiesw.com>*
*__Project__: ah-auth-plugin*
*__Company__: PanjieSW*

Defines actions related to authentication process
*********************************************
 */
var authenticateAction, signupAction;

authenticateAction = {
  name: "authenticate",
  description: "Authenticate a user",
  inputs: {
    required: ['login', 'password'],
    optional: []
  },
  blockedConnectionTypes: [],
  outputExample: {
    token: 'The user payload encoded with JSON Web Token'
  },
  run: function(api, connection, next) {
    return api.Auth.authenticate(connection.params.login, connection.params.password).then(function(token) {
      return connection.response.token = token;
    })["catch"](function(err) {
      connection.error = err;
      if (err.status) {
        return connection.rawConnection.responseHttpCode = err.status;
      }
    })["finally"](function() {
      next(connection, true);
    });
  }
};

signupAction = {
  name: "signup",
  description: "Sign a new user up",
  inputs: {
    required: ['data'],
    optional: []
  },
  blockedConnectionTypes: [],
  outputExample: {},
  run: function(api, connection, next) {
    return api.Auth.signUp(connection.params.data, 'password', true).then(function(response) {
      if (response) {
        return connection.rawConnection.responseHttpCode = 201;
      }
    })["catch"](function(err) {
      connection.error = err;
      if (err.status) {
        return connection.rawConnection.responseHttpCode = err.status;
      }
    })["finally"](function() {
      next(connection, true);
    });
  }
};

exports.authenticate = authenticateAction;

exports.signup = signupAction;
