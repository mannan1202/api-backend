import bcrypt from 'bcrypt';
import { db } from '../../utils/db.js';

export const findUserByEmail = async (email) => {
  return await db.user.findUnique({ where: { email } });
};

export const createUserByEmailAndPassword = async (user) => {
  user.password = bcrypt.hashSync(user.password, 12);
  return await db.user.create({ data: user });
};

export const findUserById = async (id) => {
  return await db.user.findUnique({ where: { id } });
};
