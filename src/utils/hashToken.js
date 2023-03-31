import crypto from 'crypto';

export const hashToken = (token) => {
  console.log(token);
  return crypto.createHash('sha512').update(token).digest('hex');
};
