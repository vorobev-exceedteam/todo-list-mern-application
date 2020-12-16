import authAPI from '../api/authAPI';
import { createAction } from '@reduxjs/toolkit';
import getErrorPayload from '../utills/getErrorPayload';

export const loginPending = createAction('auth/login/pending');
export const loginSuccess = createAction('auth/login/success');
export const loginFailure = createAction('auth/login/failure');

export const signupPending = createAction('auth/signup/pending');
export const signupSuccess = createAction('auth/signup/success');
export const signupFailure = createAction('auth/signup/failure');

export const refreshPending = createAction('auth/refresh/pending');
export const refreshSuccess = createAction('auth/refresh/success');
export const refreshFailure = createAction('auth/refresh/failure');

export const logoutPending = createAction('auth/logout/pending');
export const logoutSuccess = createAction('auth/logout/success');
export const logoutFailure = createAction('auth/logout/failure');

const getRefreshToken = () => {
  const user = JSON.parse(localStorage.getItem('user'));
  if (!user)
    return '';
  return user.refreshJWT;
};

export const login = (data) => async (dispatch) => {
  try {
    dispatch(loginPending());
    const response = await authAPI.post('/login', {
      name: data.username,
      password: data.password,
    });
    dispatch(loginSuccess(response.data.content));
  } catch (err) {
    dispatch(loginFailure(getErrorPayload(err)));
  }
};

export const signup = (data) => async (dispatch) => {
  try {
    dispatch(signupPending());
    await authAPI.post('/signup', {
      name: data.username,
      email: data.email,
      password: data.password,
    });
    dispatch(signupSuccess());
  } catch (err) {
    dispatch(signupFailure(getErrorPayload(err)));
  }
};

export const refresh = () => async (dispatch) => {
  try {
    dispatch(refreshPending());
    const response = await authAPI.post('/refresh', {
      refreshJWT: getRefreshToken(),
    });
    dispatch(refreshSuccess(response.data.content));
  } catch (err) {
    dispatch(refreshFailure(getErrorPayload(err)));
  }
};

export const logout = () => async (dispatch) => {
  try {
    dispatch(logoutPending());
    localStorage.removeItem('user');
    dispatch(logoutSuccess());
  } catch (err) {
    dispatch(logoutFailure(getErrorPayload(err)));
  }
};




