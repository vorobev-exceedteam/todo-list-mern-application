import React, { memo } from 'react';
import { useSelector } from 'react-redux';
import './ErrorBoundary.sass';

const ErrorBoundary = (props) => {

  const globalState = useSelector(state => state);

  const isError = globalState.status === 'error';

  const checkError = (error) => {
    switch (error.type) {
      case 'InternalServerError':
        return true;
      case 'NotFound':
        return true;
      default:
        return false;
    }
  };

  const isShown = isError ? checkError(globalState.error) : false;


  if (isShown)
    return (
      <div className='error-container'>
        <h1>Something went wrong</h1>
        <h2>{globalState.error.statusCode}</h2>
        <h3>{globalState.error.message}</h3>
      </div>
    );

  return props.children;
};

export default memo(ErrorBoundary);
