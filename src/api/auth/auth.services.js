import { db } from '../../utils/db.js';
import { hashToken } from '../../utils/hashToken.js';

// used to create refresh token
export const addRefreshTokenToWhiteList = (
  jti,
  refreshToken,
  userId
) => {
  console.log(refreshToken);
  return db.refreshToken.create({
    data: {
      id: jti,
      hashedToken: hashToken(refreshToken),
      userId,
    },
  });
};

// verify the token within the db
export const findRefreshTokenById = async (id) => {
  return await db.refreshToken.findUnique({
    where: {
      id,
    },
  });
};

//soft delete token after usage
export const deleteRefreshToken = async (id) => {
  return await db.refreshToken.update({
    where: { id },
    data: {
      revoked: true,
    },
  });
};

//revoke all refresh tokens of user
export const revokeTokens = async (userId) => {
  return await db.refreshToken.update({
    where: {
      userId,
    },
    data: {
      revoke: true,
    },
  });
};
