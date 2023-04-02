var crypto = require('crypto');
const {
    validateUserPhoneNumber,
    validateEmail,
    validatePassword,
    validateUsername
} = require('../utils/formater')
const {
    SEND_MAIL,
    SEND_OTP,
    POST_SEND_EMAIL,
    OTP_EMAIL,
    GET_GOOGLE_OAUTH2_TOKEN,
    GET_GOOGLE_OAUTH2_SCOPE,
    SEND_NEW_PASSWORD_REQUEST,
    NEW_PASSWORD_REQUEST_EMAIL,
} = require('../variables/general');
const {
    generateAccessToken,
    generateRefreshToken,
    SequelizeErrorHandling,
    generateOTP,
    renewToken,
    SequelizeRollback,
    getGoogleAuthURL,
    generateGooglePass,
} = require('../utils/functions');
const { MasterUser } = require('../models/user/master_user');
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
    INVALID_USERNAME
} = require('../variables/responseMessage');
const { POSTRequest } = require('../utils/axios/post');
const {
    checkCredentialTokenOTP,
    checkCredentialToken,
    checkNewPasswordRequestEligibility } = require('../utils/middleware');
const { db } = require('../config/index');
const { GETRequest } = require('../utils/axios/get');
const { Op } = require("sequelize");
const { uuid } = require('uuidv4');

const InitCredentialRoute = (app) => {

    /*POST Method
        * ROUTE: /{version}/auth/pw/forgot
        * This route submit the email of the users that forgot their password
        */
    app.post(`/v${process.env.APP_MAJOR_VERSION}/auth/pw/forgot`, async (req, res) => {

        if (!req.body) return res.sendStatus(400);
        if (!req.body.email) return res.status(400).send(INVALID_EMAIL);

        // Request find one to the database via sequelize function
        await MasterUser.findOne({ where: { email: req.body.email } })
            .then(async (user) => {
                if (!user) return res.status(404).send(USER_NOT_FOUND);

                // put the necessary user info here
                const recoveryToken = uuid();
                const userInfo = {
                    username: user.username,
                    fullName: user.fullName,
                    email: user.email,
                    token: recoveryToken
                }

                // save the token in the session
                if (!req.session.recoveryTokens) req.session.recoveryTokens = [];
                req.session.recoveryTokens.push(recoveryToken);

                // send email OTP to user
                const result = await POSTRequest({
                    endpoint: process.env.APP_MAILER_HOST_PORT,
                    url: SEND_MAIL,
                    data: {
                        receiver: req.body.email,
                        subject: NEW_PASSWORD_REQUEST_EMAIL,
                        mailType: SEND_NEW_PASSWORD_REQUEST,
                        props: userInfo
                    },
                    logTitle: POST_SEND_EMAIL
                });

                if (!result) return res.status(404).send(UNIDENTIFIED_ERROR);
                if (result.httpCode === 500) return res.sendStatus(500);
                if (result.error) return res.status(result.httpCode).send(result.errContent);

                return res.sendStatus(250);
            }).catch((err) => {
                SequelizeErrorHandling(err, res);
            });

    });

    /*POST Method
    * ROUTE: /{version}/auth/pw/token
    * This route check the password token eligibility to validate user right for their password
    */
    app.post(`/v${process.env.APP_MAJOR_VERSION}/auth/pw/new`, checkNewPasswordRequestEligibility, (req, res) => {
        return res.sendStatus(202);
    });

    /*POST Method
    * ROUTE: /{version}/auth/token
    * This route refresh/renew the access token by generating a new one and replace it in the session.
    */
    app.post(`/v${process.env.APP_MAJOR_VERSION}/auth/token`, (req, res) => {
        // check query param availability
        if (!req.body) return res.sendStatus(400);
        if (!req.body.credentialToken) return res.sendStatus(401);
        const { result, err, status } = renewToken(req.body.credentialToken, req.session.refreshTokens);
        if (status !== 200) return res.status(status).send(err);
        return res.status(status).json(result);
    });

    /*POST Method
    * ROUTE: /{version}/auth/verify/otp
    * This route is used to verify the OTP input by the user.
    */
    app.post(`/v${process.env.APP_MAJOR_VERSION}/auth/verify/otp`, checkCredentialTokenOTP, (req, res) => {
        // check query param availability
        if (!req.body) return res.sendStatus(400);
        if (!req.body.credentialToken) return res.status(400).send(UNIDENTIFIED_ERROR);
        if (new Date().getTime() >= req.user.OTPExpiration) return res.status(403).json(OTP_EXPIRED);
        if (req.body.OTPInput !== req.user.OTP) return res.status(403).json(OTP_UNMATCH);

        // If OTP valid, redirect to renew token
        const { result, err, status } = renewToken(req.body.credentialToken, req.session.refreshTokens);
        if (status !== 200) return res.status(status).send(err);
        return res.status(status).json(result);
    });

    /*POST Method
    * ROUTE: /{version}/auth/login
    * This route authenticates the user by verifying a username and password.
    * After the username and password is verified, it will generate the access token and refresh token
    * The tokens can be use to manage the authentication flow of the user
    */
    app.post(`/v${process.env.APP_MAJOR_VERSION}/auth/login`, async (req, res) => {
        // check query param availability
        if (!req.body) return res.sendStatus(400);
        // Get the request body
        const reqUser = req.body;
        // Request find one to the database via sequelize function
        await MasterUser.findOne({ where: { username: reqUser.username } })
            .then((user) => {
                if (!user) return res.status(404).send(USER_NOT_FOUND);
                crypto.pbkdf2(reqUser.password, user.salt, 310000, 32, 'sha256', async function (err, hashedPassword) {
                    if (err) res.status(500).send(err);
                    if (!crypto.timingSafeEqual(user.hashedPassword, hashedPassword)) return res.status(403).send(WRONG_PASSWORD_INPUT);
                    if (!req.session.refreshTokens) req.session.refreshTokens = [];

                    // put the necessary user info here
                    const userInfo = {
                        username: user.username,
                        fullName: user.fullName,
                        email: user.email,
                        OTP: generateOTP().toString(),
                        OTPExpiration: new Date().getTime() + 1000 * 60 * 3, //Expired in 3 min
                        OTPVerified: false
                    }

                    // send email OTP to user
                    const result = await POSTRequest({
                        endpoint: process.env.APP_MAILER_HOST_PORT,
                        url: SEND_MAIL,
                        data: {
                            receiver: user.email,
                            subject: OTP_EMAIL,
                            mailType: SEND_OTP,
                            props: userInfo
                        },
                        logTitle: POST_SEND_EMAIL
                    });

                    if (!result) return res.status(404).send(UNIDENTIFIED_ERROR);
                    if (result.httpCode === 500) return res.sendStatus(500);
                    if (result.error) return res.status(result.httpCode).send(result.errContent);

                    // token will only save the desired user info
                    const accessToken = generateAccessToken(userInfo);
                    const refreshToken = generateRefreshToken({
                        username: userInfo.username,
                        fullName: userInfo.fullName,
                        phoneNumber: userInfo.phoneNumber,
                        email: userInfo.email
                    });

                    req.session.refreshTokens.push(refreshToken);
                    res.status(200).json({
                        credentialToken: {
                            accessToken: accessToken,
                            refreshToken: refreshToken
                        }
                    });
                });
            }).catch((err) => {
                SequelizeErrorHandling(err, res);
            });
    });

    /*GET Method
    * ROUTE: /{version}/auth/google
    * This route authenticates the user by verifying user google account.
    *
    * An authentication form will be prompted in the client service, which
    * The strategy will proccess the data of the user's google account.
    */
    app.get(`/v${process.env.APP_MAJOR_VERSION}/auth/google/url`, (req, res) => {
        return res.send(getGoogleAuthURL());
    })

    app.get(`/v${process.env.APP_MAJOR_VERSION}/auth/google/callback`, async (req, res) => {
        if (!req.query) return res.status(404).send(UNIDENTIFIED_ERROR);
        if (!req.query.code) return res.status(404).send(UNIDENTIFIED_ERROR);
        const code = req.query.code;

        // fetch OAUTH token
        const token = await POSTRequest({
            endpoint: "https://oauth2.googleapis.com",
            url: "/token",
            data: {
                code,
                client_id: process.env.APP_GOOGLE_CLIENT_ID,
                client_secret: process.env.APP_GOOGLE_CLIENT_SECRET,
                redirect_uri: `${process.env.APP_GOOGLE_CLIENT_AUTHORIZED_CALLBACK_URI}/v${process.env.APP_MAJOR_VERSION}/auth/google/callback`,
                grant_type: "authorization_code",
            },
            logTitle: GET_GOOGLE_OAUTH2_TOKEN
        });

        if (!token) return res.status(404).send(UNIDENTIFIED_ERROR);
        if (token.httpCode === 500) return res.sendStatus(500);
        if (token.error) return res.status(token.httpCode).send(token.errContent);

        return res.status(200).json(token);
    });

    app.post(`/v${process.env.APP_MAJOR_VERSION}/auth/google/login`, async (req, res) => {
        // check query param availability
        if (!req.body) return res.sendStatus(400);
        if (!req.session.refreshTokens) req.session.refreshTokens = [];
        // get OAUTH token
        const googleUser = await GETRequest({
            endpoint: "https://www.googleapis.com",
            url: `/oauth2/v1/userinfo?alt=json&access_token=${req.body.access_token}`,
            headers: {
                Authorization: `Bearer ${req.body.id_token}`,
            },
            logTitle: GET_GOOGLE_OAUTH2_SCOPE
        });

        if (!googleUser) return res.status(404).send(UNIDENTIFIED_ERROR);
        if (googleUser.httpCode === 500) return res.sendStatus(500);
        if (googleUser.error) return res.status(googleUser.httpCode).send(googleUser.errContent);

        // Generate the salt
        var salt = crypto.randomBytes(16);
        // Adding salt before encrypting the password
        // Hash the password with the SHA256 encryption function
        crypto.pbkdf2(generateGooglePass(), salt, 310000, 32, 'sha256', async function (err, hashedPassword) {
            if (err) return res.status(400).send(err);
            const trx = await db.transaction();
            try {
                const user = await MasterUser.findOne({
                    where: {
                        [Op.or]: [
                            { googleId: googleUser.response.id },
                            { email: googleUser.response.email }
                        ]
                    },
                    transaction: trx
                });

                var newUser = null;
                if (!user) {
                    newUser = await MasterUser.create({
                        username: googleUser.response.email,
                        fullName: googleUser.response.email,
                        googleId: googleUser.response.id,
                        email: googleUser.response.email,
                        profilePictureURI: googleUser.response.picture,
                        hashedPassword: hashedPassword,
                        salt: salt
                    }, { transaction: trx });

                    await trx.commit();
                } else newUser = user;

                // put the necessary user info here
                const userInfo = {
                    username: newUser.username,
                    fullName: newUser.fullName,
                    email: newUser.email,
                    OTP: generateOTP().toString(),
                    OTPExpiration: new Date().getTime() + 1000 * 60 * 3, //Expired in 3 min
                    OTPVerified: false
                }

                // send email OTP to user
                const result = await POSTRequest({
                    endpoint: process.env.APP_MAILER_HOST_PORT,
                    url: SEND_MAIL,
                    data: {
                        receiver: newUser.email,
                        subject: OTP_EMAIL,
                        mailType: SEND_OTP,
                        props: userInfo
                    },
                    logTitle: POST_SEND_EMAIL
                });

                if (!result) return res.status(404).send(UNIDENTIFIED_ERROR);
                if (result.httpCode === 500) return res.sendStatus(500);
                if (result.error) return res.status(result.httpCode).send(result.errContent);

                // token will only save the desired user info
                const accessToken = generateAccessToken(userInfo);
                const refreshToken = generateRefreshToken({
                    username: userInfo.username,
                    fullName: userInfo.fullName,
                    phoneNumber: userInfo.phoneNumber,
                    email: userInfo.email
                });

                return res.status(200).json({
                    credentialToken: {
                        accessToken: accessToken,
                        refreshToken: refreshToken
                    }
                });
            } catch (error) {
                await SequelizeRollback(trx, error);
                return res.status(500).send(error);
            }
        });
    });

    /* POST /{version}/auth/signup
    *
    * This route creates a new user account.
    *
    * A desired username and password are submitted to this route via the client service.
    * The password is hashed and then a new user record is inserted into the database. If the record is
    * successfully created, the user will be logged in.
    */
    app.post(`/v${process.env.APP_MAJOR_VERSION}/auth/signup`, async (req, res) => {
        // check query param availability
        if (!req.body) return res.sendStatus(400);

        // Validate req body
        if (!validateUsername(req.body.username)) return res.status(400).send(INVALID_USERNAME);
        if (!validateEmail(req.body.email)) return res.status(400).send(INVALID_EMAIL);
        if (!validatePassword(req.body.password)) return res.status(400).send(INVALID_PASSWORD);

        // Generate the salt
        var salt = crypto.randomBytes(16);
        // Adding salt before encrypting the password
        // Hash the password with the SHA256 encryption function
        crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', async function (err, hashedPassword) {
            if (err) return res.status(400).send(err);
            const trx = await db.transaction();
            try {
                const user = await MasterUser.findOne({
                    where: {
                        [Op.or]: [
                            { username: req.body.username },
                            { email: req.body.email }
                        ]
                    },
                    transaction: trx
                });

                if (!user) {
                    await MasterUser.create({
                        username: req.body.username,
                        fullName: req.body.username,
                        email: req.body.email,
                        hashedPassword: hashedPassword,
                        salt: salt
                    }, { transaction: trx }).then(async function (newUser) {
                        await trx.commit();
                        return res.sendStatus(200);
                    });
                } else if (req.body.email === user.dataValues.email) return res.status(409).send(EMAIL_HAS_ALREADY_BEEN_USED);
                else return res.status(409).send(USER_HAS_ALREADY_BEEN_CREATED);
            } catch (error) {
                await SequelizeRollback(trx, error);
                return res.status(500).send(UNIDENTIFIED_ERROR);
            }
        });
    });

    /* POST /{version}/auth/logout
    *
    * This route will delete the refresh token from the session and log the user out.
    *
    */
    app.post(`/v${process.env.APP_MAJOR_VERSION}/auth/logout`, checkCredentialToken, (req, res) => {
        // check query param availability
        if (!req.body) return res.sendStatus(400);
        if (!req.session.refreshTokens) return res.sendStatus(403);

        const refreshTokens = req.session.refreshTokens.filter(token => token === req.body.credentialToken.refreshToken);
        if (!refreshTokens || Object.keys(refreshTokens).length === 0) return res.sendStatus(500);

        const removedIndex = req.session.refreshTokens.indexOf(refreshTokens);
        req.session.refreshTokens.splice(removedIndex, 1);
        return res.sendStatus(204)
    })
}

module.exports = {
    InitCredentialRoute
}