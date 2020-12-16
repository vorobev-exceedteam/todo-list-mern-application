const { MongoMemoryServer } = require('mongodb-memory-server');
const User = require('../models/user.model')
const mongoose = require('mongoose');
const commons = require('./commons');
const app = require('../app');
const request = require('supertest');
const statusCodes = require('../utills/statusCodes');
// const { ValidationError, RefreshedTokenInvalid } = require('../utills/Errors');
// const jwt = require('jsonwebtoken');

jasmine.DEFAULT_TIMEOUT_INTERVAL = 10000;
jest.setTimeout(60000);
jest.mock('redis', () => jest.requireActual('redis-mock'));

let mongoServer;
opts = {
  poolSize: 10000,
  bufferMaxEntries: 0,
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useMongoClient: true,
};

beforeAll(async () => {
  mongoServer = new MongoMemoryServer();
  const mongoUri = await mongoServer.getUri();
  await mongoose.connect(mongoUri, opts, (err) => {
    if (err) console.error(err);
  });
});

describe('User module tests', () => {
  test('Login with default user', async () => {
    await commons.createUser(commons.defaultUser);
    const response = await request(app)
      .post('/auth/login')
      .send({ name: commons.defaultUser.name, password: commons.defaultUser.password });
    expect(response.body.status).not.toBe('error');
    expect(response.statusCode).toBe(statusCodes.OK);
  });

  test('Signup new user', async () => {
    const randomUser = commons.getRandomUser();
    const response = await request(app).post('/auth/signup').send(randomUser);
    expect(await User.exists({name: randomUser.name, email: randomUser.email})).toBeTruthy();
    expect(response.body.status).not.toBe('error');
    expect(response.statusCode).toBe(statusCodes.CREATED);
  });

  test('Refresh with default user', async () => {
    const tokens = await commons.getTokensForUser(commons.defaultUser);
    const response = await request(app).post('/auth/refresh').send({ refreshJWT: tokens[1] });
    expect(response.body.status).not.toBe('error');
    expect(response.statusCode).toBe(statusCodes.OK);
  });

  test('Login with not existing user', async () => {
    await commons.cleanExceptDefaultUser();
    const randomUser = commons.getRandomUser();
    const response = await request(app)
      .post('/auth/login')
      .send({ name: randomUser.name, password: randomUser.password });
    expect(response.body.error.type).toBe('ValidationError');
    expect(response.body.status).toBe('error');
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
  });

  test('Login without password', async () => {
    await commons.cleanExceptDefaultUser();
    const randomUser = commons.getRandomUser();
    const response = await request(app).post('/auth/login').send({ name: randomUser.name, password: '' });
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
  });

  test('Login without name', async () => {
    await commons.cleanExceptDefaultUser();
    const randomUser = commons.getRandomUser();
    const response = await request(app).post('/auth/login').send({ name: '', password: randomUser.password });
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
  });

  test('Signup with existent user', async () => {
    await commons.cleanExceptDefaultUser();
    const defaultUser = commons.getUser(commons.defaultUser);
    const response = await request(app)
      .post('/auth/signup')
      .send({ name: defaultUser.name, password: defaultUser.password, email: defaultUser.email });
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
  });

  test('Signup without name', async () => {
    await commons.cleanExceptDefaultUser();
    const randomUser = commons.getRandomUser();
    const response = await request(app)
      .post('/auth/signup')
      .send({ password: randomUser.password, email: randomUser.email });
    expect( await User.exists({email: randomUser.email})).toBeFalsy();
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
  });

  test('Signup without password', async () => {
    await commons.cleanExceptDefaultUser();
    const randomUser = commons.getRandomUser();
    const response = await request(app)
      .post('/auth/signup')
      .send({ name: '', password: randomUser.password, email: randomUser.email });
    expect( await User.exists({name: randomUser.name})).toBeFalsy();
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
  });

  test('Signup without email', async () => {
    await commons.cleanExceptDefaultUser();
    const randomUser = commons.getRandomUser();
    const response = await request(app)
      .post('/auth/signup')
      .send({ name: randomUser.name, password: randomUser.password, });
    expect( await User.exists({name: randomUser.name})).toBeFalsy();
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
  });

  test('Signup with invalid email', async () => {
    await commons.cleanExceptDefaultUser();
    const randomUser = commons.getRandomUser();
    const response = await request(app)
      .post('/auth/signup')
      .send({ name: randomUser.name, password: randomUser.password, email: 'wefawrgtaergawrg' });
    expect( await User.exists({name: randomUser.name})).toBeFalsy();
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('ValidationError');
    expect(response.statusCode).toBe(statusCodes.BAD_REQUEST);
  });

  test('Refresh with invalid token', async () => {
    const tokens = await commons.getTokensForUser(commons.getRandomUser());
    await commons.cleanExceptDefaultUser();
    const response = await request(app).post('/auth/refresh').send({ refreshJWT: tokens[1] });
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('TokenInvalid');
    expect(response.statusCode).toBe(statusCodes.UNAUTHORIZED);
  });

  test('Refresh without token', async () => {
    await commons.cleanExceptDefaultUser();
    const response = await request(app).post('/auth/refresh').send({ });
    expect(response.body.status).toBe('error');
    expect(response.body.error.type).toBe('TokenInvalid');
    expect(response.statusCode).toBe(statusCodes.UNAUTHORIZED);
  });
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongoServer.stop();
});
