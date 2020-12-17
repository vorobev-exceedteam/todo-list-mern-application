const User = require('../models/user.model');
const Task = require('../models/task.model');
const createRedisTokens = require('../utills/createRedisTokens');
const bcrypt = require('bcrypt');
const redis = require('redis');
const JWTR = require('jwt-redis').default;

const defaultUser = {
  name: 'test123',
  email: 'test@test.com',
  password: 'test123',
  passwordHash: bcrypt.hashSync('test123', 8),
};

const createUser = async (user) => {
  await User.create({
    name: user.name,
    email: user.email,
    passwordHash: bcrypt.hashSync(user.password, 8),
  });
};

const getUser = async (user) => {
  let users = await User.find({ name: user.name });
  if (users.length === 0) {
    await createUser(user);
    return getUser(user);
  } else {
    return users[0];
  }
};

const clearTasks = async (user) => {
  if (!user) {
    return Task.deleteMany({});
  }
  return Task.deleteMany({ userid: { $ne: user._id } });
};

const isAllTasksReceived = async (tasks, userid) => {
  const dbTasksLength = (await Task.find({ userid: userid })).length;
  switch (true) {
    case !tasks:
    case dbTasksLength !== tasks.length:
      return false;
    default:
      for (let task of tasks) {
        if (await Task.exists({ userid, name: task.name, _id: task.id, checked: task.checked })) {
          return false;
        }
      }
      break;
  }
  return true;
};

const createRandomMockTasks = async (numberOfTasks, user = defaultUser,
                                     checkedState = 'random', nameLength = 10) => {
  const userid = (await getUser(user))._id;
  let checked;
  switch (checkedState) {
    case 'random':
      checked = Math.random() < 0.5;
      break;
    case 'false':
      checked = false;
      break;
    case 'true':
      checked = true;
      break;
    default:
      break;
  }
  for (let i = 0; i < numberOfTasks; i++) {
    await Task.create({
      name: generateRandomString(nameLength),
      checked,
      userid,
    });
  }
  return Task.find({ userid });
};

const isAllTasksChecked = async (user) => {
  const tasks = await Task.find({ userid: user._id });
  for (const task of tasks) {
    if (!task.checked) {
      return false;
    }
  }
  return true;
};

// const createTasks = async (tasks) =>

const getTokensForUser = async (user) => {
  const foundUser = await getUser(user);
  const redisClient = redis.createClient();
  const jwtr = new JWTR(redisClient);
  const tokens = await createRedisTokens(jwtr, {
    id: foundUser._id,
    name: foundUser.name,
    email: foundUser.email,
    password: foundUser.passwordHash,
  });
  redisClient.quit();
  return tokens;
};

const cleanExceptDefaultUser = async () => {
  const user = await getUser(defaultUser);
  await User.deleteMany({ name: { $ne: user.name } });
};

const generateRandomString = (length) => {
  return Math.random()
    .toString(36)
    .substring(2, length + 2);
};

const getRandomUser = (nameLength = 10, emailLength = 15, passwordLength = 10) => {
  return {
    name: generateRandomString(nameLength),
    email: generateRandomString((nameLength - 5) / 2) + '@' + generateRandomString((nameLength - 5) / 2) + '.com',
    password: generateRandomString(passwordLength),
  };
};

module.exports = {
  defaultUser,
  getUser,
  createUser,
  getTokensForUser,
  cleanExceptDefaultUser,
  generateRandomString,
  getRandomUser,
  createRandomMockTasks,
  clearTasks,
  isAllTasksChecked,
  isAllTasksReceived,
};
