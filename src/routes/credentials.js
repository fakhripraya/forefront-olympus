var crypto = require('crypto');
const {
    validateUserPhoneNumber,
    validateEmail
} = require('../utils/formater')
const {
    SEND_MAIL,
    SEND_OTP,
    POST_SEND_EMAIL,
    OTP_EMAIL,
    GET_GOOGLE_OAUTH2_TOKEN,
    GET_GOOGLE_OAUTH2_SCOPE
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
    INVALID_PHONE_NUMBER,
    UNIDENTIFIED_ERROR,
    OTP_UNMATCH,
    OTP_EXPIRED,
    USER_HAS_ALREADY_BEEN_CREATED
} = require('../variables/responseMessage');
const { POSTRequest } = require('../utils/axios/post');
const { checkCredentialTokenOTP } = require('../utils/middleware');
const { db } = require('../config/index');
const { GETRequest } = require('../utils/axios/get');
const { Op } = require("sequelize");

const InitCredentialRoute = (app) => {

    /*POST Method
    * ROUTE: /{version}/auth/token
    * This route refresh/renew the access token by generating a new one and replace it in the session.
    */
    app.post(`/v${process.env.APP_MAJOR_VERSION}/auth/token`, (req, res) => {
        // check query param availability
        if (!req.body) return res.sendStatus(400);
        if (!req.body.credentialToken) return res.sendStatus(401);
        const { result, err, status } = renewToken(req.body.credentialToken, req.session.refreshTokens);
        if (status !== 200) return res.send(err).status(status);
        return res.json(result).status(status);
    });

    /*POST Method
    * ROUTE: /{version}/auth/verify/otp
    * This route is used to verify the OTP input by the user.
    */
    app.post(`/v${process.env.APP_MAJOR_VERSION}/auth/verify/otp`, checkCredentialTokenOTP, (req, res) => {
        // check query param availability
        if (!req.body) return res.sendStatus(400);
        if (!req.body.credentialToken) res.send(UNIDENTIFIED_ERROR).status(400);
        if (new Date().getTime() >= req.user.OTPExpiration) return res.json(OTP_EXPIRED).status(403);
        if (req.body.OTPInput !== req.user.OTP) return res.json(OTP_UNMATCH).status(403);

        // If OTP valid, redirect to renew token
        const { result, err, status } = renewToken(req.body.credentialToken, req.session.refreshTokens);
        if (status !== 200) return res.send(err).status(status);
        return res.json(result).status(status);
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
                if (!user) return res.send(USER_NOT_FOUND).status(404);
                crypto.pbkdf2(reqUser.password, user.salt, 310000, 32, 'sha256', async function (err, hashedPassword) {
                    if (err) res.send(err).status(500);
                    if (!crypto.timingSafeEqual(user.hashedPassword, hashedPassword)) return res.send(WRONG_PASSWORD_INPUT).status(403);
                    if (!req.session.refreshTokens) req.session.refreshTokens = [];

                    // put the necessary user info here
                    const userInfo = {
                        username: user.username,
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

                    if (!result) return res.send(UNIDENTIFIED_ERROR).status(404);
                    if (result.httpCode === 500) return res.sendStatus(500);
                    if (result.error) return res.send(result.errContent).status(result.httpCode);

                    // token will only save the desired user info
                    const accessToken = generateAccessToken(userInfo);
                    const refreshToken = generateRefreshToken({
                        username: userInfo.username,
                        phoneNumber: userInfo.phoneNumber,
                        email: userInfo.email
                    });

                    req.session.refreshTokens.push(refreshToken);
                    res.json({
                        credentialToken: {
                            accessToken: accessToken,
                            refreshToken: refreshToken
                        }
                    }).status(200);
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
        if (!req.query) return res.send(UNIDENTIFIED_ERROR).status(404);
        if (!req.query.code) return res.send(UNIDENTIFIED_ERROR).status(404);
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

        if (!token) return res.send(UNIDENTIFIED_ERROR).status(404);
        if (token.httpCode === 500) return res.sendStatus(500);
        if (token.error) return res.send(token.errContent).status(token.httpCode);

        return res.json(token).status(200);
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

        if (!googleUser) return res.send(UNIDENTIFIED_ERROR).status(404);
        if (googleUser.httpCode === 500) return res.sendStatus(500);
        if (googleUser.error) return res.send(googleUser.errContent).status(googleUser.httpCode);

        // Generate the salt
        var salt = crypto.randomBytes(16);
        // Adding salt before encrypting the password
        // Hash the password with the SHA256 encryption function
        crypto.pbkdf2(generateGooglePass(), salt, 310000, 32, 'sha256', async function (err, hashedPassword) {
            if (err) return res.send(err).status(400);
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

                if (!result) return res.send(UNIDENTIFIED_ERROR).status(404);
                if (result.httpCode === 500) return res.sendStatus(500);
                if (result.error) return res.send(result.errContent).status(result.httpCode);

                // token will only save the desired user info
                const accessToken = generateAccessToken(userInfo);
                const refreshToken = generateRefreshToken({
                    username: userInfo.username,
                    phoneNumber: userInfo.phoneNumber,
                    email: userInfo.email
                });

                return res.json({
                    credentialToken: {
                        accessToken: accessToken,
                        refreshToken: refreshToken
                    }
                }).status(200);
            } catch (error) {
                await SequelizeRollback(trx, error);
                return res.send(error).status(500);
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
        if (!validateEmail(req.body.email)) res.send(INVALID_EMAIL);
        if (!validateUserPhoneNumber(req.body.phoneNumber)) res.send(INVALID_PHONE_NUMBER);

        // Generate the salt
        var salt = crypto.randomBytes(16);
        // Adding salt before encrypting the password
        // Hash the password with the SHA256 encryption function
        crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', async function (err, hashedPassword) {
            if (err) return res.send(err).status(400);
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
                        email: req.body.email,
                        hashedPassword: hashedPassword,
                        salt: salt
                    }, { transaction: trx }).then(async function (newUser) {
                        await trx.commit();
                        return res.sendStatus(200);
                    });
                } else return res.send(USER_HAS_ALREADY_BEEN_CREATED).status(409);
            } catch (error) {
                await SequelizeRollback(trx, error);
                return res.send(UNIDENTIFIED_ERROR).status(500);
            }
        });
    });

    /* POST /{version}/auth/logout
    *
    * This route will delete the refresh token from the session and log the user out.
    *
    */
    app.delete(`/v${process.env.APP_MAJOR_VERSION}/auth/logout`, (req, res) => {
        // check query param availability
        if (!req.body) return res.sendStatus(400);
        if (!req.session.refreshTokens) return res.sendStatus(403);

        const refreshTokens = req.session.refreshTokens.filter(token => token !== req.body.token)
        return res.sendStatus(204)
    })
}

module.exports = {
    InitCredentialRoute
}