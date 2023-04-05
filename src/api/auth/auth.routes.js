import express from 'express';
import { v4 as uuid } from 'uuid';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { generateTokens } from '../../utils/jwt.js';
import {
  addRefreshTokenToWhiteList,
  findRefreshTokenById,
  deleteRefreshToken,
  revokeTokens,
} from './auth.services.js';
import {
  findUserByEmail,
  createUserByEmailAndPassword,
  findUserById,
} from '../users/users.services.js';
import { hashToken } from '../../utils/hashToken.js';

const router = express.Router();

router.post('/register', async (req, res, next) => {
  try {
    const { email, password, confirm_password } = req.body;
    if (!email || !password) {
      res.status(400);
      throw new Error('You must provide email and password');
    }

    const existingUser = await findUserByEmail(email);
    if (existingUser) {
      res.status(400);
      throw new Error('Email already exist');
    }

    if (password !== confirm_password) {
      res.status(400);
      throw new Error('Password and confirm password do not match');
    }

    const user = await createUserByEmailAndPassword({
      email,
      password,
    });
    const jti = uuid();
    const { accessToken, refreshToken } = await generateTokens(
      user,
      jti
    );
    await addRefreshTokenToWhiteList(jti, refreshToken, user.id);
    res.json({
      accessToken,
      refreshToken,
    });
  } catch (e) {
    next(e);
  }
});

router.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      res.status(400);
      throw new Error('You must provide email and password');
    }
    const existingUser = await findUserByEmail(email);
    if (!existingUser) {
      res.status(403);
      throw new Error('Email does not exist');
    }

    const validPassword = await bcrypt.compare(
      password,
      existingUser.password
    );
    if (!validPassword) {
      res.status(403);
      throw new Error('Invalid login credentials.');
    }

    const jti = uuid();
    const { accessToken, refreshToken } = generateTokens(
      existingUser,
      jti
    );
    await addRefreshTokenToWhiteList(
      jti,
      refreshToken,
      existingUser.id
    );

    res.json({
      accessToken,
      refreshToken,
    });
  } catch (e) {
    next(e);
  }
});

router.post('/refreshToken', async (req, res, next) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      res.status(400);
      throw new Error('Missing refresh token.');
    }
    const payload = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET
    );

    const savedRefreshToken = await findRefreshTokenById(payload.jti);

    if (!savedRefreshToken || savedRefreshToken.revoked === true) {
      res.status(401);
      throw new Error('Unauthorized');
    }

    const hashedToken = hashToken(refreshToken);
    if (hashedToken !== savedRefreshToken.hashedToken) {
      res.status(401);
      throw new Error('Unauthorized');
    }

    const user = await findUserById(payload.userId);
    if (!user) {
      res.status(401);
      throw new Error('Unauthorized');
    }

    await deleteRefreshToken(savedRefreshToken.id);
    const jti = uuid();
    const { accessToken, refreshToken: newRefreshToken } =
      generateTokens(user, jti);
    await addRefreshTokenToWhiteList(jti, newRefreshToken, user.id);

    res.json({
      accessToken,
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    next(err);
  }
});

// Move this logic where you need to revoke the tokens( for ex, on password reset)
router.post('/revokeRefreshTokens', async (req, res, next) => {
  try {
    const { userId } = req.body;
    await revokeTokens(userId);
    res.json({
      message: `Tokens revoked for user with id #${userId}`,
    });
  } catch (err) {
    next(err);
  }
});

export default router;
