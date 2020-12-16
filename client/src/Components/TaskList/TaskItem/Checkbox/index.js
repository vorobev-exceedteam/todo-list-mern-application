import React from 'react';
import b from 'b_';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faCheck } from '@fortawesome/free-solid-svg-icons';
import './Checkbox.sass';
import { useSelector } from 'react-redux';

const Checkbox = (props) => {

  const isDisabled = useSelector(state => state.status) !== 'success';


  const checkboxStyle = b('checkbox-container', 'checkbox', {
    disabled: isDisabled,
  });
  const checkmarkStyle = b('checkbox-container__checkbox', 'checkmark', {
    checked: props.isChecked,
    disabled: isDisabled,
  });
  const labelStyle = b('checkbox-container', 'label', {
    checked: props.isChecked,
    disabled: isDisabled,
  });

  return (
    <div className='checkbox-container'>
      <div onClick={props.clicked} className={checkboxStyle}>
        <FontAwesomeIcon className={checkmarkStyle} icon={faCheck} />
      </div>
      <div className={labelStyle}>{props.children}</div>
    </div>
  );
};

export default Checkbox;
