const crypto = require('crypto');

const createRedisTokens = async (jwtr, payload) => {
  const hash = crypto.createHash('sha1');
  const authJTI = hash.copy().update(payload.id.toString()).digest('base64');
  const refreshJTI = hash.update(authJTI).digest('base64')
  const authPayload = {...payload};
  const refreshPayload = {...payload};
  authPayload.jti = authJTI;
  refreshPayload.jti = refreshJTI;
  const authToken = await jwtr.sign(authPayload, process.env.AUTH_SECRET, {
    expiresIn: process.env.AUTH_TOKEN_EXPIRATION_TIME,
  });
  const refreshToken = await jwtr.sign(refreshPayload, process.env.REFRESH_SECRET, {
    expiresIn: process.env.REFRESH_TOKEN_EXPIRATION_TIME,
  });
  return [authToken, refreshToken];
};

module.exports = createRedisTokens;
