const express = require('express');
const validationHandler = require('../middleware/validation/validationHandler');
const loginValidationSchema = require('../middleware/validation/schemas/loginSchema');
const signupValidationSchema = require('../middleware/validation/schemas/signupSchema');
const userController = require('../controllers/user.controller');

const authRoutes = (jwtr) => {
  const router = express.Router();
  router.route('/login').post(validationHandler(loginValidationSchema, 'login'), userController.login(jwtr));
  router.route('/signup').post(validationHandler(signupValidationSchema, 'signup'), userController.signup);
  router.post('/refresh', userController.refresh(jwtr));
  router.post('/logout', userController.logout(jwtr));
  return router;
};

module.exports = authRoutes;
