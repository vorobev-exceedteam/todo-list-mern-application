import InputTask from '../../Components/InputTask';
import TaskList from '../../Components/TaskList';
import TaskControls from '../../Components/TaskControls';
import './Todo.sass';
import React, { memo, useMemo, useState } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { addTask } from '../../actions/taskActions';


const Todo = () => {

  const [filterState, setFilterState] = useState('All');
  const [inputTaskError, setInputTaskError] = useState(null);

  const dispatch = useDispatch();

  const keyPressHandler = (event) => {
    if (event.key === 'Enter') {
      switch (true) {
        case event.target.value.length < 1:
          setInputTaskError('Task name is required');
          break;
        case event.target.value.length > 35:
          setInputTaskError('Task name should be less than 35 characters');
          break;
        default:
          setInputTaskError(null);
          dispatch(addTask(event.target.value));
          event.target.value = '';
          break;
      }
    }
  };

  const filterHandler = (filter) => () => {
    setFilterState(filter);
  };

  const tasks = useSelector(state => state.tasks);

  const filteredTasks = useMemo(() => {
    switch (filterState) {
      case 'ToDo':
        return tasks.filter((task) => !task.checked);
      case 'Completed':
        return tasks.filter((task) => task.checked);
      default:
        return tasks;
    }
  }, [tasks, filterState]);

  return (
    <main className='todo-container'>
      <InputTask error={inputTaskError} keyPressHandler={keyPressHandler} />
      <TaskList tasks={filteredTasks} />
      <TaskControls filterState={filterState} setFilter={filterHandler} />
    </main>
  );
};

export default memo(Todo);
