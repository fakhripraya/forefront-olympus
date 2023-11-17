const jwt = require("jsonwebtoken");
const querystring = require("querystring");
const crypto = require("crypto");
const {
  SESSION_TOKEN_NOT_FOUND,
  USER_ACCESS_FORBIDDEN,
} = require("../variables/responseMessage");
const {
  sessionStore,
} = require("forefront-polus/src/config");

function generateAccessToken(user) {
  return jwt.sign(
    JSON.stringify(user),
    process.env.APP_ACCESS_TOKEN_SECRET
  );
}

function generateRefreshToken(user) {
  return jwt.sign(
    JSON.stringify(user),
    process.env.APP_REFRESH_TOKEN_SECRET
  );
}

function hashPassword(password, salt) {
  return new Promise((resolve, reject) => {
    const iterations = 310000;
    const keylen = 32;
    const digest = "sha256";

    crypto.pbkdf2(
      password,
      salt,
      iterations,
      keylen,
      digest,
      (err, key) => {
        if (err) {
          reject(err);
        } else {
          resolve(key);
        }
      }
    );
  });
}

async function renewToken(
  credentialToken,
  userSession,
  userSessionID
) {
  // here we will take the refresh token from the credential token object
  var result = { result: null, err: null, status: null };
  let refreshToken = credentialToken.refreshToken;

  // Check the session token
  if (!userSession)
    return (result = {
      result: null,
      err: USER_ACCESS_FORBIDDEN,
      status: 403,
    });
  if (userSession.refreshToken !== refreshToken)
    return (result = {
      result: null,
      err: SESSION_TOKEN_NOT_FOUND,
      status: 401,
    });

  // Verify the JWT token
  try {
    const user = jwt.verify(
      refreshToken,
      process.env.APP_REFRESH_TOKEN_SECRET
    );

    // create renewed user
    const renewedUser = {
      userId: user.userId,
      username: user.username,
      fullName: user.fullName,
      phoneNumber: user.phoneNumber,
      email: user.email,
      OTPVerified: true,
    };

    // generate new token
    const accessToken = generateAccessToken(renewedUser);
    refreshToken = generateRefreshToken(renewedUser);

    // assign the new token in the session
    const response = await sessionStore.set(
      userSessionID,
      {
        ...userSession,
        refreshToken: refreshToken,
      },
      (err) => {
        if (err) throw new Error(err.toString());
        return (result = {
          result: {
            user: renewedUser,
            credentialToken: {
              accessToken: accessToken,
              refreshToken: refreshToken,
            },
            sid: userSessionID,
          },
          err: null,
          status: 200,
        });
      }
    );

    return response;
  } catch (err) {
    if (err)
      return (result = {
        result: null,
        err: err,
        status: 500,
      });
  }
}

function getGoogleAuthURL() {
  const rootUrl =
    "https://accounts.google.com/o/oauth2/v2/auth";
  const options = {
    // redirect_uri: `${process.env.APP_GOOGLE_CLIENT_AUTHORIZED_CALLBACK_URI}/v${process.env.APP_MAJOR_VERSION}/auth/google/callback`,
    redirect_uri: `${process.env.APP_GOOGLE_CLIENT_AUTHORIZED_CALLBACK_URI}`,
    client_id: process.env.APP_GOOGLE_CLIENT_ID,
    access_type: "offline",
    response_type: "code",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/userinfo.profile",
      "https://www.googleapis.com/auth/userinfo.email",
    ].join(" "),
  };

  return `${rootUrl}?${querystring.stringify(options)}`;
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000);
}

function generateGooglePass() {
  return Math.random().toString(36).slice(-8);
}

module.exports = {
  generateOTP,
  generateGooglePass,
  generateAccessToken,
  renewToken,
  hashPassword,
  generateRefreshToken,
  getGoogleAuthURL,
};
