import React, { memo } from 'react';
import './SubmitButton.sass';

const SubmitButton = (props) => {
  return (
    <>
      <input className='submit-button' type='submit' value={props.children} />
    </>);
};

export default memo(SubmitButton);
