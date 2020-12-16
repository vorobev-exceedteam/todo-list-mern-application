import './App.css';
import Todo from './Containers/Todo';
import React, { useEffect } from 'react';
import Navigation from './Components/Navigation';
import { Redirect, Route, Switch } from 'react-router-dom';
import Login from './Components/Login';
import Loading from './Components/Loading/';
import { Container } from 'react-bootstrap';
import Signup from './Components/Signup';
import { refresh } from './actions/authActions';
import { useDispatch, useSelector } from 'react-redux';
import { fetchTasks } from './actions/taskActions';
import ErrorBoundary from './Components/ErrorBoundary';


function App() {

  const { authStatus, status } = useSelector(state => state);
  const dispatch = useDispatch();

  useEffect(() => {
    switch (status) {
      case 'refresh':
        dispatch(refresh());
        break;
      case 'idle':
        dispatch(fetchTasks());
        break;
      default:
        break;
    }

  }, [dispatch, status]);


  const isLoggedIn = authStatus === 'authorized';
  const isInitState = authStatus === 'initial';

  return (
    <div className="App">
      <ErrorBoundary>
        <Navigation />
        <Container>
          {isInitState ? <Loading /> :
            <Switch>
              <Route path={'/login'}>
                {isLoggedIn ? <Redirect to={'/'} /> : <Login />}
              </Route>
              <Route path={'/signup'}>
                {isLoggedIn ? <Redirect to={'/'} /> : <Signup />}
              </Route>
              <Route path={'/'}>
                {isLoggedIn ? <Todo /> : <Redirect to={'/login'} />}
              </Route>
            </Switch>}
        </Container>
      </ErrorBoundary>
    </div>
  );
}

export default App;
