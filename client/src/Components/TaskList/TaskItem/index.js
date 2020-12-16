import React, { memo } from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faTrashAlt } from '@fortawesome/free-solid-svg-icons';
import './TaskItem.sass';
import { changeTaskState, removeTask } from '../../../actions/taskActions';
// import {Checkbox} from "@material-ui/core";
import b from 'b_';
import Checkbox from './Checkbox';
import { useDispatch, useSelector } from 'react-redux';

const TaskItem = (props) => {
  const stateStatus = useSelector(state => state.status);
  const isDisabled = (stateStatus === 'idle') || (stateStatus === 'pending');
  const iconStyle = b('task-item', 'delete-icon', { disabled: isDisabled });

  const dispatch = useDispatch();

  return (
    <div className='task-item'>
      {/*<Checkbox disabled={isDisabled} onChange={() => dispatch(changeTaskState(props.id))}*/}
      {/*          checked={props.isChecked} color='primary'/>*/}
      <Checkbox isChecked={props.isChecked}
                clicked={() => dispatch(changeTaskState(props.id))}>{props.taskText}</Checkbox>
      <div className={iconStyle}>
        <FontAwesomeIcon icon={faTrashAlt}
                         onClick={() => dispatch(removeTask(props.id))} />
      </div>
    </div>
  );
};


export default memo(TaskItem);
