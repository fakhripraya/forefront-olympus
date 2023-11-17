var crypto = require("crypto");
const {
  validateEmail,
  validatePassword,
  validateUsername,
} = require("../utils/validator");
const {
  SEND_MAIL,
  SEND_OTP,
  POST_SEND_EMAIL,
  OTP_EMAIL,
  GET_GOOGLE_OAUTH2_TOKEN,
  GET_GOOGLE_OAUTH2_SCOPE,
  SEND_NEW_PASSWORD_REQUEST,
  NEW_PASSWORD_REQUEST_EMAIL,
  X_SID,
} = require("../variables/general");
const {
  generateAccessToken,
  generateRefreshToken,
  generateOTP,
  renewToken,
  getGoogleAuthURL,
  generateGooglePass,
  hashPassword,
} = require("../utils/functions");
const {
  MasterUser,
} = require("forefront-polus/src/models/user/master_user");
const {
  WRONG_PASSWORD_INPUT,
  USER_NOT_FOUND,
  INVALID_EMAIL,
  UNIDENTIFIED_ERROR,
  OTP_UNMATCH,
  OTP_EXPIRED,
  USER_HAS_ALREADY_BEEN_CREATED,
  INVALID_PASSWORD,
  EMAIL_HAS_ALREADY_BEEN_USED,
  INVALID_USERNAME,
  USER_UNAUTHORIZED,
  UNDEFINED_QUERY_PARAM,
  INTERNAL_ERROR_CANT_COMMUNICATE,
  USER_ACCESS_FORBIDDEN,
} = require("../variables/responseMessage");
const { POSTRequest } = require("../utils/axios/post");
const {
  checkCredentialTokenOTP,
  checkCredentialToken,
  checkNewPasswordRequestEligibility,
} = require("../utils/middleware");
const { db } = require("../config/index");
const { GETRequest } = require("../utils/axios/get");
const { Op } = require("sequelize");
const { uuid } = require("uuidv4");
const { sessionStore } = require("../config/index");
const {
  SequelizeErrorHandling,
  SequelizeRollback,
} = require("forefront-polus/src/utils/functions");

const InitCredentialRoute = (app) => {
  /*POST Method
   * ROUTE: /{version}/auth/pw/forgot
   * This route submit the email of the users that forgot their password
   */
  app.post(
    `/v${process.env.APP_MAJOR_VERSION}/auth/pw/forgot`,
    async (req, res) => {
      // check query param availability
      if (!req.body)
        return res.status(400).send(UNIDENTIFIED_ERROR);
      if (!req.body.email)
        return res.status(400).send(INVALID_EMAIL);

      // Request find one to the database via sequelize function
      const user = await MasterUser.findOne({
        where: { email: req.body.email },
      }).catch((err) => {
        SequelizeErrorHandling(err, res);
      });

      if (!user)
        return res.status(404).send(USER_NOT_FOUND);

      // put the necessary user info here
      const recoveryToken = uuid();
      const userInfo = {
        username: user.username,
        fullName: user.fullName,
        email: user.email,
        token: recoveryToken,
      };

      // create new session
      // save the token in the session
      req.session.recoveryInfo = userInfo;

      // send email OTP to user
      const result = await POSTRequest({
        endpoint: process.env.APP_MAILER_HOST_PORT,
        url: SEND_MAIL,
        data: {
          receiver: req.body.email,
          subject: NEW_PASSWORD_REQUEST_EMAIL,
          mailType: SEND_NEW_PASSWORD_REQUEST,
          props: userInfo,
        },
        logTitle: POST_SEND_EMAIL,
      });

      if (!result)
        return res.status(404).send(UNIDENTIFIED_ERROR);
      if (result.httpCode === 500)
        return res.sendStatus(500);
      if (result.error)
        return res
          .status(result.httpCode)
          .send(result.errContent);

      res.status(200).json({
        sid: req.sessionID,
      });
    }
  );

  /*POST Method
   * ROUTE: /{version}/auth/pw/new
   * This route change the requester password based on the password submitted in the request body
   */
  app.post(
    `/v${process.env.APP_MAJOR_VERSION}/auth/pw/new`,
    checkNewPasswordRequestEligibility,
    async (req, res) => {
      // check query param availability
      if (!req.body)
        return res.status(400).send(UNIDENTIFIED_ERROR);
      if (!validatePassword(req.body.newPassword))
        return res.status(400).send(INVALID_PASSWORD);
      if (!validatePassword(req.body.confirmPassword))
        return res.status(400).send(INVALID_PASSWORD);

      // Generate the salt
      var salt = crypto.randomBytes(16);
      var hashedPassword;
      // Adding salt before encrypting the password
      // Hash the password with the SHA256 encryption function
      try {
        hashedPassword = await hashPassword(
          req.body.newPassword,
          salt
        );
      } catch (error) {
        return res.status(500).send(error);
      }

      const trx = await db.transaction();
      try {
        await MasterUser.update(
          {
            hashedPassword: hashedPassword,
            salt: salt,
          },
          {
            where: {
              email: req.user.session.recoveryInfo.email,
            },
            lock: true,
            transaction: trx,
          }
        );

        await trx.commit();
        return res.sendStatus(200);
      } catch (error) {
        await SequelizeRollback(trx, error);
        SequelizeErrorHandling(error, res);
      }
    }
  );

  /*POST Method
   * ROUTE: /{version}/auth/token
   * This route refresh/renew the access token by generating a new one and replace it in the session.
   */
  app.post(
    `/v${process.env.APP_MAJOR_VERSION}/auth/token`,
    checkCredentialToken,
    async (req, res) => {
      // check query param availability
      // in here if the user dont have cred token in the body, we will send 401 instead of 403
      // its to mark that user is not authorized yet
      if (!req.body)
        return res.status(400).send(UNIDENTIFIED_ERROR);
      if (!req.body.credentialToken)
        return res.status(401).send(USER_UNAUTHORIZED);

      // Renew the token
      const { result, err, status } = await renewToken(
        req.body.credentialToken,
        req.user.session,
        req.headers[X_SID]
      );

      if (status !== 200)
        return res.status(status).send(err);
      return res.status(status).json(result);
    }
  );

  /*POST Method
   * ROUTE: /{version}/auth/verify/otp
   * This route is used to verify the OTP input by the user.
   */
  app.post(
    `/v${process.env.APP_MAJOR_VERSION}/auth/verify/otp`,
    checkCredentialTokenOTP,
    async (req, res) => {
      // check query param availability
      // in here if the user dont have cred token in the body, we will send 403 instead of 401
      // its to mark that user is forbidden to continue the flow
      if (!req.body)
        return res.status(400).send(UNIDENTIFIED_ERROR);
      if (!req.body.credentialToken)
        return res.status(403).send(USER_ACCESS_FORBIDDEN);

      // Check the OTP validation
      if (new Date().getTime() >= req.user.OTPExpiration)
        return res.status(403).json(OTP_EXPIRED);
      if (req.body.OTPInput !== req.user.OTP)
        return res.status(403).json(OTP_UNMATCH);

      // Renew the token
      // If OTP valid, redirect to renew token
      const { result, err, status } = await renewToken(
        req.body.credentialToken,
        req.user.session,
        req.headers[X_SID]
      );

      if (status !== 200)
        return res.status(status).send(err);
      return res.status(status).json(result);
    }
  );

  /*POST Method
   * ROUTE: /{version}/auth/login
   * This route authenticates the user by verifying a username and password.
   * After the username and password is verified, it will generate the access token and refresh token
   * The tokens can be use to manage the authentication flow of the user
   */
  app.post(
    `/v${process.env.APP_MAJOR_VERSION}/auth/login`,
    async (req, res) => {
      // check query param availability
      if (!req.body)
        return res.status(400).send(UNIDENTIFIED_ERROR);

      // Get the request body
      const reqUser = req.body;

      // Request find one to the database via sequelize function
      // if the user login with email, allow it
      var hashedPassword;
      var user;
      try {
        user = await MasterUser.findOne({
          where: {
            [Op.or]: [
              { username: reqUser.username },
              { email: reqUser.username },
            ],
          },
        });

        if (!user)
          return res.status(404).send(USER_NOT_FOUND);
      } catch (error) {
        SequelizeErrorHandling(error, res);
      }

      try {
        hashedPassword = await hashPassword(
          reqUser.password,
          user.salt
        );
        if (
          !crypto.timingSafeEqual(
            user.hashedPassword,
            hashedPassword
          )
        )
          return res.status(403).send(WRONG_PASSWORD_INPUT);
      } catch (error) {
        return res.status(500).send(error);
      }

      // put the necessary user info here
      const userInfo = {
        userId: user.id,
        username: user.username,
        fullName: user.fullName,
        phoneNumber: user.phoneNumber,
        email: user.email,
        OTP: generateOTP().toString(),
        OTPExpiration: new Date().getTime() + 1000 * 60 * 3, //Expired in 3 min
        OTPVerified: false,
      };

      // send email OTP to user
      const result = await POSTRequest({
        endpoint: process.env.APP_MAILER_HOST_PORT,
        url: SEND_MAIL,
        data: {
          receiver: user.email,
          subject: OTP_EMAIL,
          mailType: SEND_OTP,
          props: userInfo,
        },
        logTitle: POST_SEND_EMAIL,
      });

      if (!result)
        return res.status(404).send(UNIDENTIFIED_ERROR);
      if (result.httpCode === 500)
        return res
          .status(500)
          .send(INTERNAL_ERROR_CANT_COMMUNICATE);
      if (result.error)
        return res
          .status(result.httpCode)
          .send(result.errContent);

      try {
        // token will only save the desired user info
        const accessToken = generateAccessToken(userInfo);
        const refreshToken = generateRefreshToken({
          userId: userInfo.userId,
          username: userInfo.username,
          fullName: userInfo.fullName,
          phoneNumber: userInfo.phoneNumber,
          email: userInfo.email,
        });

        // create new session
        // assign the newly generated refresh token
        // pass the session ID to the client side
        req.session.refreshToken = refreshToken;
        return res.status(200).json({
          sid: req.sessionID,
          credentialToken: {
            accessToken: accessToken,
            refreshToken: refreshToken,
          },
        });
      } catch (error) {
        return res.status(500).send(error);
      }
    }
  );

  /* POST /{version}/auth/signup
   *
   * This route creates a new user account.
   *
   * A desired username and password are submitted to this route via the client service.
   * The password is hashed and then a new user record is inserted into the database. If the record is
   * successfully created, the user will be logged in.
   */
  app.post(
    `/v${process.env.APP_MAJOR_VERSION}/auth/signup`,
    async (req, res) => {
      // check query param availability
      if (!req.body)
        return res.status(400).send(UNIDENTIFIED_ERROR);

      // Validate req body
      if (!validateUsername(req.body.username))
        return res.status(400).send(INVALID_USERNAME);
      if (!validateEmail(req.body.email))
        return res.status(400).send(INVALID_EMAIL);
      if (!validatePassword(req.body.password))
        return res.status(400).send(INVALID_PASSWORD);

      // Generate the salt
      var salt = crypto.randomBytes(16);
      var hashedPassword;
      // Adding salt before encrypting the password
      // Hash the password with the SHA256 encryption function
      try {
        hashedPassword = await hashPassword(
          req.body.password,
          salt
        );
      } catch (error) {
        return res.status(500).send(error);
      }

      const trx = await db.transaction();
      try {
        const user = await MasterUser.findOne({
          where: {
            [Op.or]: [
              { username: req.body.username },
              { email: req.body.email },
            ],
          },
        });

        if (
          user &&
          req.body.email === user.dataValues.email
        )
          return res
            .status(409)
            .send(EMAIL_HAS_ALREADY_BEEN_USED);
        else if (
          user &&
          req.body.username === user.dataValues.username
        ) {
          return res
            .status(409)
            .send(USER_HAS_ALREADY_BEEN_CREATED);
        }

        await MasterUser.create(
          {
            username: req.body.username,
            fullName: req.body.username,
            email: req.body.email,
            hashedPassword: hashedPassword,
            salt: salt,
          },
          { lock: true, transaction: trx }
        );

        await trx.commit();
        return res.sendStatus(200);
      } catch (error) {
        await SequelizeRollback(trx, error);
        SequelizeErrorHandling(error, res);
      }
    }
  );

  /*GET Method
   * ROUTE: /{version}/auth/google/url
   * This route authenticates the user by verifying user google account.
   *
   * An authentication form will be prompted in the client service, called consent screen
   * the user need to submit the google credential in the client after that the google will process the submission
   * and will invoke the callback route in the server
   */
  app.get(
    `/v${process.env.APP_MAJOR_VERSION}/auth/google/url`,
    (req, res) => {
      return res.send(getGoogleAuthURL());
    }
  );

  /*POST Method
   * ROUTE: /{version}/auth/google/callback
   * This route authenticates the user by verifying user google account.
   *
   * This callback route will be invoke after user credential is submitted from the client side
   * in this process server will save the user session in the DB and token will be passed to the browser cookie in the client
   */
  app.post(
    `/v${process.env.APP_MAJOR_VERSION}/auth/google/callback`,
    async (req, res) => {
      if (!req.query)
        return res.status(404).send(UNDEFINED_QUERY_PARAM);
      if (!req.query.code)
        return res.status(404).send(UNDEFINED_QUERY_PARAM);
      const code = req.query.code;
      // fetch OAUTH token
      const token = await POSTRequest({
        endpoint: "https://oauth2.googleapis.com",
        url: "/token",
        data: {
          code,
          client_id: process.env.APP_GOOGLE_CLIENT_ID,
          client_secret:
            process.env.APP_GOOGLE_CLIENT_SECRET,
          redirect_uri: `${process.env.APP_GOOGLE_CLIENT_AUTHORIZED_CALLBACK_URI}`,
          grant_type: "authorization_code",
        },
        logTitle: GET_GOOGLE_OAUTH2_TOKEN,
      });

      if (!token)
        return res.status(404).send(UNIDENTIFIED_ERROR);
      if (token.httpCode === 500)
        return res.sendStatus(500);
      if (token.error)
        return res
          .status(token.httpCode)
          .send(token.errContent);

      // get OAUTH token
      const googleUser = await GETRequest({
        endpoint: "https://www.googleapis.com",
        url: `/oauth2/v1/userinfo?alt=json&access_token=${token.response.access_token}`,
        headers: {
          Authorization: `Bearer ${token.response.id_token}`,
        },
        logTitle: GET_GOOGLE_OAUTH2_SCOPE,
      });

      if (!googleUser)
        return res.status(404).send(UNIDENTIFIED_ERROR);
      if (googleUser.httpCode === 500)
        return res.sendStatus(500);
      if (googleUser.error)
        return res
          .status(googleUser.httpCode)
          .send(googleUser.errContent);

      // Generate the salt
      var salt = crypto.randomBytes(16);
      var hashedPassword;
      // Adding salt before encrypting the password
      // Hash the password with the SHA256 encryption function
      try {
        hashedPassword = await hashPassword(
          generateGooglePass(),
          salt
        );
      } catch (error) {
        return res.status(500).send(error);
      }

      var newUser = null;
      const trx = await db.transaction();
      try {
        const user = await MasterUser.findOne({
          where: {
            [Op.or]: [
              { googleId: googleUser.response.id },
              { email: googleUser.response.email },
            ],
          },
        });

        if (!user) {
          newUser = await MasterUser.create(
            {
              username: googleUser.response.email,
              fullName: googleUser.response.email,
              googleId: googleUser.response.id,
              email: googleUser.response.email,
              profilePictureURI:
                googleUser.response.picture,
              hashedPassword: hashedPassword,
              salt: salt,
            },
            { lock: true, transaction: trx }
          );

          await trx.commit();
        } else newUser = user;
      } catch (error) {
        await SequelizeRollback(trx, error);
        SequelizeErrorHandling(error, res);
      }

      try {
        // put the necessary user info here
        const userInfo = {
          userId: newUser.id,
          username: newUser.username,
          fullName: newUser.fullName,
          phoneNumber: newUser.phoneNumber,
          email: newUser.email,
          OTPVerified: true,
        };

        // token will only save the desired user info
        const accessToken = generateAccessToken(userInfo);
        const refreshToken = generateRefreshToken(userInfo);
        req.session.refreshToken = refreshToken;
        return res.status(200).json({
          sid: req.sessionID,
          user: userInfo,
          credentialToken: {
            accessToken: accessToken,
            refreshToken: refreshToken,
          },
        });
      } catch (error) {
        return res.status(500).send(error);
      }
    }
  );

  /* POST /{version}/auth/logout
   *
   * This route will delete the refresh token from the session and log the user out.
   *
   */
  app.post(
    `/v${process.env.APP_MAJOR_VERSION}/auth/logout`,
    async (req, res) => {
      if (!req.headers[X_SID]) return res.status(200);

      await sessionStore.destroy(req.headers[X_SID], () => {
        return res.sendStatus(200);
      });
    }
  );
};

module.exports = {
  InitCredentialRoute,
};
