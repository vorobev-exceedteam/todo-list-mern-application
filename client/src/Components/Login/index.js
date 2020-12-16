import React, { memo, useMemo } from 'react';
import { useForm } from 'react-hook-form';
import InputField from '../Auth/InputField';
import SubmitButton from '../Auth/SubmitButton';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import './Login.sass';
import { useDispatch, useSelector } from 'react-redux';
import * as actions from '../../actions/authActions';


const Login = () => {

  const globalState = useSelector(state => state);

  const schema = useMemo(() => yup.object()
    .shape({
      username: yup
        .string('Username should be a text')
        .required('Username is required')
        .max(20, `Username should be less than 20 characters`),
      password: yup
        .string('Password should be a text')
        .required('Password is required')
        .min(3, `Password should be at least 3 characters`)
        .max(20, `Password should be less than 20 characters`),
    }), [],
  );

  const dispatch = useDispatch();
  const onSubmit = data => {
    dispatch(actions.login(data));
  };

  const { register, handleSubmit, errors } = useForm({
    resolver: yupResolver(schema),
  });

  if (globalState.status === 'error' && !Object.keys(errors).length) {
    if (globalState.error.type === 'ValidationError') {
      globalState.error.details.forEach(serverValidation => {
        switch (serverValidation.path) {
          case 'login/name':
            errors.username = { message: serverValidation.message };
            break;
          case 'login/password':
            errors.password = { message: serverValidation.message };
            break;
          default:
            break;
        }
      });

    }
  }

  return (
    <div className='login-container'>
      <form onSubmit={handleSubmit(onSubmit)}>
        <InputField placeholder={'Enter your username'} name={'username'} label={'Username'}
                    error={errors?.username?.message} validation={register} />
        <InputField placeholder={'Enter your password'} name={'password'} label={'Password'}
                    error={errors?.password?.message} validation={register} type={'password'} />
        <SubmitButton>Login</SubmitButton>
      </form>
    </div>
  );
};

export default memo(Login);
