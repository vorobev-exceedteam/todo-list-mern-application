import React, { memo } from 'react';
import { Spinner } from 'react-bootstrap';
import './Loading.sass';

const Loading = (props) => {
  return (
    <div className={'loading-container'}>
      <Spinner animation='border' />
      <span>Loading...</span>
    </div>
  );
};

export default memo(Loading);
