require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
// const { NotFound } = require('./utills/Errors');
const path = require('path');
const redis = require('redis');
const JWTR = require('jwt-redis').default;

const redisClient = redis.createClient();

const jwtr = new JWTR(redisClient);

const taskRoutes = require('./routes/task.route');
const authRoutes = require('./routes/user.route');

const errorHandler = require('./middleware/errorHandler');

const app = express();

const port = process.env.PORT || 9000;

if (process.env.NODE_ENV !== 'test') {
  const mongoDB = process.env.MONGODB_URI;
  mongoose
    .connect(mongoDB, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    })
    .catch((err) => {
      console.error(err.stack);
      process.exit(1);
    });
}

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

app.use(express.static(path.join(__dirname, 'client', 'build')));

app.use('/tasks', taskRoutes(jwtr));
app.use('/auth', authRoutes(jwtr));

// app.use('*', (req, res, next) => next(new NotFound('Route does not exist')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client', 'build', 'index.html'));
});

app.use(errorHandler);

app.listen(port, () => {
  console.log('Server is up and running on port number ' + port);
});

module.exports = app;
