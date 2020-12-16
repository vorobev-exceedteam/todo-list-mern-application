import React from 'react';
import b from 'b_';
import './RadioBadge.sass';

const RadioBadge = (props) => {
  return <button className={b('radio-badge', { activated: props.activated })} disabled={props.isDisabled}
                 onClick={props.onClick}>{props.children}</button>;
};

export default RadioBadge;
