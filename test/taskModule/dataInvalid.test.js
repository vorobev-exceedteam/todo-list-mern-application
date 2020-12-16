const { MongoMemoryServer } = require('mongodb-memory-server');
const mongoose = require('mongoose');
const commons = require('../commons');
const app = require('../../app');
const request = require('supertest');
const statusCodes = require('../../utills/statusCodes');
const Task = require('../../models/task.model');

jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
jest.setTimeout(60000);
jest.mock('redis', () => jest.requireActual('redis-mock'));

let mongoServer;
opts = {
  poolSize: 10000,
  bufferMaxEntries: 0,
  useNewUrlParser: true,
  useUnifiedTopology: true,
  // useMongoClient: true,
};

beforeAll(async () => {
  mongoServer = new MongoMemoryServer();
  const mongoUri = await mongoServer.getUri();
  await mongoose.connect(mongoUri, opts, (err) => {
    if (err) console.error(err);
  });
});

describe('Task module: operations with invalid data', () => {
  test('Add task without name', async () => {
    await commons.clearTasks();
    const user = await commons.getUser(commons.defaultUser);
    const tokens = await commons.getTokensForUser(user);
    const response = await request(app)
      .post('/tasks/add')
      .send({ data: { checked: false }, authJWT: tokens[0] });
    expect(await Task.exists({ userid: user.id, checked: false, name: 'test' })).toBeFalsy();
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
  });
  test('Add task without checked', async () => {
    await commons.clearTasks();
    const user = await commons.getUser(commons.defaultUser);
    const tokens = await commons.getTokensForUser(user);
    const response = await request(app)
      .post('/tasks/add')
      .send({ data: { name: 'test' }, authJWT: tokens[0] });
    expect(await Task.exists({ userid: user.id, checked: false, name: 'test' })).toBeFalsy();
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
  });
  test('Change state of task without id', async () => {
    await commons.clearTasks();
    const user = await commons.getUser(commons.defaultUser);
    const tokens = await commons.getTokensForUser(user);
    const taskId = (await commons.createRandomMockTasks(1, user, 'false'))[0]._id;
    const response = await request(app).patch('/tasks/change').send({ data: {}, authJWT: tokens[0] });
    const task = await Task.find({ _id: taskId });
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
    expect(task[0].checked).toBeFalsy();
  });
  test('Delete task without id', async () => {
    await commons.clearTasks();
    const user = await commons.getUser(commons.defaultUser);
    const tokens = await commons.getTokensForUser(user);
    const task = (await commons.createRandomMockTasks(1, user))[0];
    const response = await request(app)
      .delete('/tasks/')
      .send({ data: { }, authJWT: tokens[0] });
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
    expect(await Task.exists(task)).toBeTruthy();
  });
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});
