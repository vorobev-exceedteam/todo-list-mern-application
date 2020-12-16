import React, { memo, useMemo } from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { filterBadges } from '../../constants/filterBadges';
import { checkAllTasks, clearCompletedTask } from '../../actions/taskActions';
import './TaskControls.sass';
import b from 'b_';
// import {Button, ButtonGroup} from "@material-ui/core";
import RadioBadge from './RadioBadge';

const TaskControls = (props) => {

  const tasks = useSelector(state => state.tasks);
  const tasksLeft = useMemo(() => tasks.filter(task => !task.checked).length, [tasks]);
  const tasksCompleted = tasks.length - tasksLeft;
  const dispatch = useDispatch();
  const hasTasks = (tasksLeft + tasksCompleted) > 0;

  const stateStatus = useSelector(state => state.status);
  const isDisabled = (stateStatus === 'idle') || (stateStatus === 'pending');
  const isHidden = tasksCompleted < 1;

  const badges = filterBadges.map(badge => {
    return <RadioBadge activated={badge === props.filterState} key={badge}
                       onClick={props.setFilter(badge)}>{badge}</RadioBadge>;
  });

  const tasksControlsElement = (
    <div className={b('task-controls')}>
      <p className={b('task-controls', 'text-button', { disabled: isDisabled })}
         onClick={() => dispatch(checkAllTasks())}>{tasksLeft} tasks left
      </p>
      <div className={b('task-controls', 'badges-group')}>{badges}</div>
      <p className={b('task-controls', 'text-button', {
        disabled: isDisabled || isHidden,
        hidden: isHidden,
      })}
         onClick={() => dispatch(clearCompletedTask())}>
        Clear completed
      </p>
    </div>
  );

  return hasTasks ? tasksControlsElement : null;
};

export default memo(TaskControls);
