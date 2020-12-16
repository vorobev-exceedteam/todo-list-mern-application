import React, { memo } from 'react';
import { Link } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import Navbar from 'react-bootstrap/Navbar';
import Nav from 'react-bootstrap/Nav';
import { logout } from '../../actions/authActions';

const Navigation = (props) => {
  const isLoggedIn = useSelector(state => state.authStatus) === 'authorized';

  const dispatch = useDispatch();


  return (
    <Navbar bg="light" expand>
      <Navbar.Brand>ToDo</Navbar.Brand>
      <Navbar.Toggle />
      <Nav className="ml-auto">
        {isLoggedIn ?
          <Nav.Link key={'logout'} onClick={() => dispatch(logout())}>Logout</Nav.Link>
          :
          [<Nav.Link key={'login'} as={Link} to='/login'>Login</Nav.Link>,
            <Nav.Link key={'signup'} as={Link} to='/signup'>Signup</Nav.Link>]}
      </Nav>
    </Navbar>
  );
};

export default memo(Navigation);
