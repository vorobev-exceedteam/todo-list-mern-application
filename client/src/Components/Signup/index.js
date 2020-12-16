import React, { useMemo } from 'react';
import { useForm } from 'react-hook-form';
import InputField from '../Auth/InputField';
import SubmitButton from '../Auth/SubmitButton';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { useHistory } from 'react-router-dom';
import './Signup.sass';
import { useDispatch, useSelector } from 'react-redux';
import * as actions from '../../actions/authActions';


const Signup = () => {

  const globalState = useSelector(state => state);

  const schema = useMemo(() => yup.object()
    .shape({
      username: yup
        .string('Username should be a text')
        .required('Username is required')
        .max(35, `Username should be less than 35 characters`),
      email: yup
        .string('Email should be a text')
        .required('Email is required')
        .email('Should be a valid email address')
        .max(35, `Email should be less than 35 characters`),
      password: yup
        .string('Password should be a text')
        .required('Password is required')
        .min(3, `Password should be at least 3 characters`)
        .max(35, `Password should be less than 35 characters`),
    }), [],
  );

  const history = useHistory();
  // const [isValidationError, setValidationError] = useState(false);

  const { register, handleSubmit, errors } = useForm({
    resolver: yupResolver(schema),
  });
  const dispatch = useDispatch();
  const onSubmit = data => {
    dispatch(actions.signup(data));
    history.push('/');

  };

  if (globalState.status === 'error' && !Object.keys(errors).length) {
    if (globalState.error.type === 'ValidationError') {
      globalState.error.details.forEach(serverValidation => {
        switch (serverValidation.path) {
          case 'signup/username':
            errors.username = { message: serverValidation.message };
            break;
          case 'signup/email':
            errors.email = { message: serverValidation.message };
            break;
          case 'signup/password':
            errors.password = { message: serverValidation.message };
            break;
          default:
            break;
        }
      });

    }
  }


  return (
    <div className='signup-container'>
      <form onSubmit={handleSubmit(onSubmit)}>
        <InputField placeholder={'Enter your username'} name={'username'} label={'Username'}
                    error={errors?.username?.message} validation={register} />
        <InputField placeholder={'Enter your email'} name={'email'} label={'Email'}
                    error={errors?.email?.message} validation={register} type={'email'} />
        <InputField placeholder={'Enter your password'} name={'password'} label={'Password'}
                    error={errors?.password?.message} validation={register} type={'password'} />
        <SubmitButton>SignUp</SubmitButton>
      </form>
    </div>
  );
};

export default Signup;
