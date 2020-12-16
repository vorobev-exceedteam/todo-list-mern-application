import { createReducer } from '@reduxjs/toolkit';
import * as taskActions from '../actions/taskActions';
import * as authActions from '../actions/authActions';
import initialState from '../constants/initialState';

const isPendingAction = (action) => {
  return action.type.endsWith('/pending');
};

const isSuccessAction = (action) => {
  const isSuccessTaskAction = !(action.type.includes('fetchTasks') || action.type.includes('auth'));
  return action.type.endsWith('/success') && isSuccessTaskAction;
};

const isFailureAction = (action) => {
  return action.type.endsWith('/failure');
};

const rootReducer = createReducer(initialState, (builder) => {
  builder
    .addCase(authActions.loginSuccess, (state, action) => {
      localStorage.setItem('user', JSON.stringify(action.payload));
      state.status = 'idle';
      state.authStatus = 'authorized';
    })
    .addCase(authActions.logoutSuccess, (state) => {
      localStorage.removeItem('user');
      state.tasks = [];
      state.status = 'waiting';
      state.authStatus = 'unauthorized';
    })
    .addCase(authActions.signupSuccess, (state) => {
      state.status = 'waiting';
      state.authStatus = 'unauthorized';
    })
    .addCase(authActions.refreshSuccess, (state, action) => {
      localStorage.setItem('user', JSON.stringify(action.payload));
      state.authStatus = 'authorized';
      state.status = 'idle';
    })
    .addCase(taskActions.fetchTasksSuccess, (state, action) => {
      state.status = 'success';
      state.authStatus = 'authorized';
      state.tasks = action.payload;
    })
    .addMatcher(isPendingAction, ((state) => {
      state.status = 'loading';
      state.error = null;
    }))
    .addMatcher(isSuccessAction, ((state) => {
      state.status = 'idle';
      state.error = null;
    }))
    .addMatcher(isFailureAction, ((state, action) => {
      switch (action.payload.type) {
        case 'AuthTokenExpired':
          state.authStatus = 'unauthorized';
          state.status = 'refresh';
          break;
        case 'TokenInvalid':
        case 'RefreshTokenExpired':
          state.authStatus = 'unauthorized';
          state.status = 'waiting';
          break;
        default:
          state.status = 'error';
          break;
      }
      state.error = action.payload;

    }));

});

export default rootReducer;
