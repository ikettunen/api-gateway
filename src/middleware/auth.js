const { expressjwt: jwt } = require('express-jwt');
const logger = require('pino')({ level: process.env.LOG_LEVEL || 'info' });

/**
 * Middleware to check JWT tokens
 */
const jwtCheck = jwt({
  secret: process.env.JWT_SECRET || 'default_jwt_secret',
  algorithms: ['HS256'],
  credentialsRequired: true,
  requestProperty: 'user'
});

/**
 * Custom error handler for unauthorized requests
 */
function handleAuthError(err, req, res, next) {
  if (err.name === 'UnauthorizedError') {
    logger.warn(`Unauthorized request to ${req.path}`, { error: err.message });
    return res.status(401).json({
      error: {
        message: 'Authentication required',
        details: err.message
      }
    });
  }
  next(err);
}

module.exports = {
  jwtCheck,
  handleAuthError
};
