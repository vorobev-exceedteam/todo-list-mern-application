const crypto = require('crypto');

const destroyRedisTokens = async (jwtr, userid) => {
  const hash = crypto.createHash('sha1');
  const authJTI = hash.copy().update(userid).digest('base64');
  const refreshJTI = hash.update(authJTI).digest('base64')
  await jwtr.destroy(authJTI);
  await jwtr.destroy(refreshJTI);
};

module.exports = destroyRedisTokens;
