
/*
 *Auth Middleware Initializer
*__Author__: Panjie SW <panjie@panjiesw.com>*
*__Project__: ah-auth-plugin*
*__Company__: PanjieSW*

Defines middleware for Auth plugin.
*********************************************
 */
exports.auth_middleware = function(api, next) {

  /*
  Adds ``authenticate`` property to actions and do request verification
  for authenticated token based on its value (if it is truthy
  then the action can't be accessed by unauthenticated user).
  
  If the verification process is passed, the decoded user payload
  will be available in ``connection.user`` to the actions.
   */
  var authenticationMiddleware;
  authenticationMiddleware = function(connection, actionTemplate, callback) {
    var check, credentials, error, parts, scheme, token;
    if (actionTemplate.authenticate === true) {
      check = null;
      if (connection.rawConnection.req) {
        check = connection.rawConnection.req;
      } else {
        check = connection['mock'];
      }
      if (check.headers && check.headers['authorization']) {
        parts = check.headers['authorization'].split(' ');
        if (parts.length === 2) {
          scheme = parts[0];
          credentials = parts[1];
          if (/^Token$/i.test(scheme)) {
            token = credentials;
          }
          api.Auth.verifyToken(token, {}).then(function(decoded) {
            connection.user = decoded;
            return callback(connection, true);
          })["catch"](function(err) {
            var error;
            error = new api.Auth.UnauthorizedError(err.message, 'invalid_token');
            connection.error = error;
            connection.rawConnection.responseHttpCode = error.status;
            return callback(connection, false);
          });
          return;
        } else {
          error = new api.Auth.UnauthorizedError('Format is Authorization: Token [token]', 'credentials_bad_format');
          connection.error = error;
          connection.rawConnection.responseHttpCode = error.status;
          callback(connection, false);
          return;
        }
      } else {
        error = new api.Auth.UnauthorizedError('No Authorization header was found', 'credentials_required');
        connection.error = error;
        connection.rawConnection.responseHttpCode = error.status;
        callback(connection, false);
        return;
      }
    }
    return callback(connection, true);
  };
  //api.actions.preProcessors.push(authenticationMiddleware);
  api.actions.addPreProcessor(authenticationMiddleware);
  return next();
};
