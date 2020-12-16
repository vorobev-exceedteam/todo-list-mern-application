import React, { memo } from 'react';
import b from 'b_';
import './InputField.sass';
import { Alert } from 'react-bootstrap';


const InputField = (props) => {
  return (
    <div className='input-field-container'>
      <label className={b('input-field-container', 'label')} htmlFor="text-input">{props.label}</label>
      <input
        name={props.name}
        placeholder={props.placeholder}
        className={b('input-field-container', 'text-field')}
        id="text-input"
        type={props.type || 'text'}
        ref={props.validation} />
      <Alert transition variant='danger' show={!!props.error}>{props.error}</Alert>
    </div>
  );
};

export default memo(InputField);
