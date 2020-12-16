import React, { memo } from 'react';
import './InputTask.sass';
import { useSelector } from 'react-redux';
import b from 'b_';


const InputTask = (props) => {

  const stateStatus = useSelector(state => state.status);
  const isDisabled = (stateStatus === 'idle') || (stateStatus === 'pending');

  return (
    <div className='input-task'>
      <input
        disabled={isDisabled}
        type="input"
        className="input-task__field"
        placeholder="Enter your task name here"
        onKeyPress={props.keyPressHandler} />
      {props.error ? <p className={b('input-task', 'error')}>{props.error}</p> : null}
    </div>
  );
};

export default memo(InputTask);
