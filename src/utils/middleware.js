const jwt = require('jsonwebtoken');
const {
    PLEASE_VERIFY_OTP,
    INVALID_RECOVERY_TOKEN,
    CANT_VALIDATE_RECOVERY_TOKEN,
    SESSION_TOKEN_NOT_FOUND,
    USER_UNAUTHORIZED } = require('../variables/responseMessage');

// Check the new password request eligibility
function checkNewPasswordRequestEligibility(req, res, next) {
    if (!req.session.recoveryInfo) return res.status(500).send(CANT_VALIDATE_RECOVERY_TOKEN);

    const recoveryInfo = req.session.recoveryInfo.filter(userInfo => userInfo.token === req.body.recoveryToken);
    if (!recoveryInfo || Object.keys(recoveryInfo).length === 0) return res.status(403).send(INVALID_RECOVERY_TOKEN);

    next();
}

// Check the credential token middleware for OTP
function checkCredentialTokenOTP(req, res, next) {
    // Check the user session
    if (!req.session) return res.sendStatus(401);
    if (!req.session.refreshTokens) return res.status(401).send(SESSION_TOKEN_NOT_FOUND);

    // Check the JWT in the header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token === null) return res.status(401).send(USER_UNAUTHORIZED);

    // Verify JWT access token
    jwt.verify(token, process.env.APP_ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(500).send(err);
        req.user = user;
        next();
    })
}

// Check the credential token middleware
function checkCredentialToken(req, res, next) {
    // Check the user session
    if (!req.session) return res.sendStatus(401);
    if (!req.session.refreshTokens) return res.status(401).send(SESSION_TOKEN_NOT_FOUND);

    // Check the JWT in the header
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token === null) return res.status(401).send(USER_UNAUTHORIZED);

    // Verify JWT access token
    jwt.verify(token, process.env.APP_ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(500).send(err);
        if (!user.OTPVerified) return res.status(403).send(PLEASE_VERIFY_OTP);
        req.user = user;
        next();
    })
}

function handleCSRFToken(req, res, next) {
    //TODO: handle csrf later
    res.locals.csrfToken = req.csrfToken();
    next();
}

module.exports = {
    checkNewPasswordRequestEligibility,
    checkCredentialTokenOTP,
    checkCredentialToken,
    handleCSRFToken
}