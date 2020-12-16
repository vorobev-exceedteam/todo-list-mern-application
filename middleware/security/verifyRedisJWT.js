const checkDecodedCredentials = require('../../utills/checkDecodedCredentials')
const { AuthTokenInvalid } = require('../../utills/Errors');


const verifyRedisJWT = (jwtr) => async (req, res, next) => {
  try{
    const authToken = req.body.authJWT;
    if (!authToken) {
      return next(new AuthTokenInvalid());
    }
    const decoded = await jwtr.verify(authToken, process.env.AUTH_SECRET);
    const isValid = await checkDecodedCredentials(decoded);
    if (!isValid) {
      return next(new AuthTokenInvalid());
    }
    req.userid = decoded.id
    next();
  }
  catch (e) {
    e.tokenType = 'auth'
    next(e)
  }
};

module.exports = verifyRedisJWT;
