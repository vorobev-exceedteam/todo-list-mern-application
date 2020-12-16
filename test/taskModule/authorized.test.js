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

describe('Task module: operations with authorized user', () => {
  test('Add task', async () => {
    const user = await commons.getUser(commons.defaultUser);
    const tokens = await commons.getTokensForUser(user);
    const response = await request(app)
      .post('/tasks/add')
      .send({ data: { name: 'test', checked: false }, authJWT: tokens[0] });
    expect(await Task.exists({ userid: user.id, checked: false, name: 'test' })).toBeTruthy();
    expect(response.body.status).not.toBe('error');
    expect(response.statusCode).toBe(statusCodes.CREATED);
  });
  test('Change task state', async () => {
    await commons.clearTasks();
    const user = await commons.getUser(commons.defaultUser);
    const tokens = await commons.getTokensForUser(user);
    const taskId = (await commons.createRandomMockTasks(1, user, 'false'))[0]._id;
    const response = await request(app)
      .patch('/tasks/change')
      .send({ data: { id: taskId }, authJWT: tokens[0] });
    const task = await Task.find({ _id: taskId });
    expect(response.statusCode).toBe(statusCodes.OK);
    expect(response.body.status).not.toBe('error');
    expect(task[0].checked).toBeTruthy();
  });
  test('Get tasks', async () => {
    const user = await commons.getUser(commons.defaultUser);
    const tokens = await commons.getTokensForUser(user);
    await commons.clearTasks();
    await commons.createRandomMockTasks(10, user);
    const response = await request(app)
      .post('/tasks/')
      .send({ data: { name: 'test' }, authJWT: tokens[0] });
    expect(response.statusCode).toBe(statusCodes.OK);
    expect(response.body.status).not.toBe('error');
    expect(response.body.content).not.toBeUndefined();
    expect( await commons.isAllTasksReceived(response.body.content, user._id)).toBeTruthy();
  });
  test('Delete task', async () => {
    await commons.clearTasks();
    const user = await commons.getUser(commons.defaultUser);
    const tokens = await commons.getTokensForUser(user);
    const task = (await commons.createRandomMockTasks(1, user))[0];
    const response = await request(app)
      .delete('/tasks/')
      .send({ data: { id: task._id }, authJWT: tokens[0] });
    expect(response.statusCode).toBe(statusCodes.OK);
    expect(response.body.status).not.toBe('error');
    expect(await Task.exists(task)).toBeFalsy();
  });
  test('Check all tasks', async () => {
    await commons.clearTasks();
    const user = await commons.getUser(commons.defaultUser);
    const tokens = await commons.getTokensForUser(user);
    await commons.createRandomMockTasks(10, user, 'false');
    const response = await request(app).patch('/tasks/checkAll').send({ authJWT: tokens[0] });
    expect(response.statusCode).toBe(statusCodes.OK);
    expect(response.body.status).not.toBe('error');
    expect(await commons.isAllTasksChecked(user)).toBeTruthy();
  });
  test('Delete checked tasks', async () => {
    await commons.clearTasks();
    const user = await commons.getUser(commons.defaultUser);
    const tokens = await commons.getTokensForUser(user);
    await commons.createRandomMockTasks(10, user, 'true');
    await commons.createRandomMockTasks(10, user, 'false');
    const response = await request(app).delete('/tasks/clearCompleted').send({ authJWT: tokens[0] });
    expect(response.statusCode).toBe(statusCodes.OK);
    expect(response.body.status).not.toBe('error');
    expect(await commons.isAllTasksChecked(user)).toBeFalsy();
  });
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});
