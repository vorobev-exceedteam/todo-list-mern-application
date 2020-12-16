const mongoose = require('mongoose');
const jwtr = require('jwt-redis');
const {
  GeneralError,
  InternalServerError,
  ValidationError,
  UnauthorizedError,
  AuthTokenExpired,
  AuthTokenInvalid,
  RefreshedTokenExpired,
  RefreshedTokenInvalid,
} = require('../utills/Errors');

const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  let error;
  switch (true) {
    case err instanceof GeneralError:
      error = err;
      break;
    case err instanceof mongoose.Error.ValidationError:
      error = new ValidationError(err.message);
      break;
    case err instanceof jwtr.TokenDestroyedError:
      switch (err.tokenType) {
        case 'auth':
          error = new AuthTokenExpired();
          break;
        case 'refresh':
          error = new RefreshedTokenExpired();
          break;
        default:
          error = new UnauthorizedError('Token expired');
          break;
      }
      break;
    case err instanceof jwtr.TokenInvalidError:
      switch (err.tokenType) {
        case 'auth':
          error = new AuthTokenInvalid();
          break;
        case 'refresh':
          error = new RefreshedTokenInvalid();
          break;
        default:
          error = new UnauthorizedError('Token invalid');
          break;
      }
      break;
    default:
      error = new InternalServerError('Internal server error');
      break;
  }
  return res.status(error.statusCode).json(error.prepareForSend());
};

module.exports = errorHandler;
