import React, { memo } from 'react';
import TaskItem from './TaskItem';
import './TaskList.sass';


const TaskList = (props) => {


  const elements = props.tasks.map((task) => {
    return <TaskItem key={task._id} id={task._id} taskText={task.name} isChecked={task.checked} />;
  });

  return (
    <div className='task-list'>
      {elements}
    </div>
  );
};

export default memo(TaskList);
