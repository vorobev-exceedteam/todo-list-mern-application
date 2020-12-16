const getErrorPayload = (error) => {
  if (!error.response?.data) {
    return { type: 'InternalServerError', statusCode: 500, message: 'Internal server error' };
  }
  return {
    ...error.response.data.error,
    statusCode: error.response.status,
  };
};

export default getErrorPayload;
