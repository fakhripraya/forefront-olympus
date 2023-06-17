const jwt = require('jsonwebtoken');
const querystring = require('querystring');
const {
    SEQUELIZE_DATABASE_ERROR,
    SEQUELIZE_VALIDATION_ERROR,
    SEQUELIZE_UNIQUE_CONSTRAINT_ERROR
} = require('../variables/dbError');
const { USER_HAS_ALREADY_BEEN_CREATED, SESSION_TOKEN_NOT_FOUND, UNIDENTIFIED_ERROR } = require('../variables/responseMessage');

function generateAccessToken(user) {
    return jwt.sign(JSON.stringify(user), process.env.APP_ACCESS_TOKEN_SECRET)
}

function generateRefreshToken(user) {
    return jwt.sign(JSON.stringify(user), process.env.APP_REFRESH_TOKEN_SECRET)
}

function renewToken(credentialToken, sessionRefreshTokens) {
    // Init result
    var result = { result: null, err: null, status: null };
    let refreshToken = credentialToken.refreshToken;

    // Check the session token 
    if (!sessionRefreshTokens) return result = { result: null, err: SESSION_TOKEN_NOT_FOUND, status: 401 };
    if (!sessionRefreshTokens.includes(refreshToken)) return result = { result: null, err: SESSION_TOKEN_NOT_FOUND, status: 401 };

    // Verify the JWT token
    jwt.verify(refreshToken, process.env.APP_REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return result = { result: null, err: err, status: 500 };
        // create renewed user
        const renewedUser = {
            userId: user.userId,
            username: user.username,
            fullName: user.fullName,
            phoneNumber: user.phoneNumber,
            email: user.email,
            OTPVerified: true
        }

        // generate new token
        const accessToken = generateAccessToken(renewedUser);
        refreshToken = generateRefreshToken(renewedUser);
        return result = {
            result: {
                user: renewedUser,
                credentialToken: {
                    accessToken: accessToken,
                    refreshToken: refreshToken
                }
            }, err: null, status: 200
        };
    })
    return result;
}

function getGoogleAuthURL() {
    const rootUrl = "https://accounts.google.com/o/oauth2/v2/auth";
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

function SequelizeErrorHandling(err, res) {
    var errMessages = [];
    // if the DB error is database error
    if (err.name === SEQUELIZE_DATABASE_ERROR) return res.status(500).send({
        code: err.parent.code,
        parentMessage: err.parent.sqlMessage,
        original: err.original.code,
        originalMessage: err.original.sqlMessage,
    });
    // if the DB error is the user input error
    if (err.name === SEQUELIZE_VALIDATION_ERROR) {
        err.errors.forEach((err) => errMessages.push(err.message));
        return res.status(400).send(errMessages);
    }
    // if the DB error is the unique constraint error
    if (err.name === SEQUELIZE_UNIQUE_CONSTRAINT_ERROR) {
        err.errors.forEach((err) => errMessages.push(err.message));
        return res.status(400).send({
            ...errMessages,
            possibility: USER_HAS_ALREADY_BEEN_CREATED
        });
    } else return res.status(400).send(err.toString());
}

function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000)
}

function generateGooglePass() {
    return Math.random().toString(36).slice(-8);
}

async function SequelizeRollback(trx, error) {
    console.log(error);
    console.log("There has been some error when commiting the transaction, rolling back...");
    await trx.rollback();
}

module.exports = {
    generateOTP,
    generateGooglePass,
    generateAccessToken,
    renewToken,
    generateRefreshToken,
    SequelizeErrorHandling,
    SequelizeRollback,
    getGoogleAuthURL
}


