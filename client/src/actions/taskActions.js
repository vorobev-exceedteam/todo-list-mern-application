import { createAction } from '@reduxjs/toolkit';
import taskAPI from '../api/taskAPI';
import getErrorPayload from '../utills/getErrorPayload';

export const fetchTasksPending = createAction('todo/fetchTasks/pending');
export const fetchTasksSuccess = createAction('todo/fetchTasks/success');
export const fetchTasksFailure = createAction('todo/fetchTasks/failure');
export const addTaskPending = createAction('todo/addTask/pending');
export const addTaskSuccess = createAction('todo/addTask/success');
export const addTaskFailure = createAction('todo/addTask/failure');
export const removeTaskPending = createAction('todo/remove/pending');
export const removeTaskSuccess = createAction('todo/remove/success');
export const removeTaskFailure = createAction('todo/remove/failure');
export const changeTaskStatePending = createAction('todo/changeTaskState/pending');
export const changeTaskStateSuccess = createAction('todo/changeTaskState/success');
export const changeTaskStateFailure = createAction('todo/changeTaskState/failure');
export const checkAllTasksPending = createAction('todo/checkAll/pending');
export const checkAllTasksSuccess = createAction('todo/checkAll/success');
export const checkAllTasksFailure = createAction('todo/checkAll/failure');
export const clearCompletedTaskPending = createAction('todo/clearCompleted/pending');
export const clearCompletedTaskSuccess = createAction('todo/clearCompleted/success');
export const clearCompletedTaskFailure = createAction('todo/clearCompleted/failure');

const addAuthJWT = () => {
  const tokens = JSON.parse(localStorage.getItem('user'));
  if (!!tokens) {
    return tokens.authJWT;
  }
  return '';
};

export const fetchTasks = () => async (dispatch) => {
  try {
    dispatch(fetchTasksPending());
    const response = await taskAPI.post('/', { authJWT: addAuthJWT() });
    dispatch(fetchTasksSuccess(response.data.content));
  } catch (err) {
    dispatch(fetchTasksFailure(getErrorPayload(err)));
  }
};

export const addTask = (name) => async (dispatch) => {
  try {
    dispatch(addTaskPending());
    await taskAPI.post('/add', {
      data: {
        name: name,
        checked: false,
      }, authJWT: addAuthJWT(),
    });
    dispatch(addTaskSuccess());
  } catch (err) {
    dispatch(addTaskFailure(getErrorPayload(err)));
  }
};

export const removeTask = (id) => async (dispatch) => {
  try {
    dispatch(removeTaskPending());
    await taskAPI.delete('/', { data: { data: { id: id }, authJWT: addAuthJWT() } });
    dispatch(removeTaskSuccess());
  } catch (err) {
    dispatch(removeTaskFailure(getErrorPayload(err)));
  }
};

export const changeTaskState = (id) => async (dispatch) => {
  try {
    dispatch(changeTaskStatePending());
    await taskAPI.patch('/change', { data: { id: id }, authJWT: addAuthJWT() });
    dispatch(changeTaskStateSuccess());
  } catch (err) {
    dispatch(changeTaskStateFailure(getErrorPayload(err)));
  }
};

export const checkAllTasks = (id) => async (dispatch) => {
  try {
    dispatch(checkAllTasksPending());
    await taskAPI.patch('/checkAll', { authJWT: addAuthJWT() });
    dispatch(checkAllTasksSuccess());
  } catch (err) {
    dispatch(checkAllTasksFailure(getErrorPayload(err)));

  }
};

export const clearCompletedTask = () => async (dispatch) => {
  try {
    dispatch(clearCompletedTaskPending());
    await taskAPI.delete('/clearCompleted', { data: { authJWT: addAuthJWT() } });
    dispatch(clearCompletedTaskSuccess());
  } catch (err) {
    dispatch(clearCompletedTaskFailure(getErrorPayload(err)));
  }
};
