const jwt = require('jsonwebtoken');
const {
    PLEASE_VERIFY_OTP,
    INVALID_RECOVERY_TOKEN,
    CANT_VALIDATE_RECOVERY_TOKEN } = require('../variables/responseMessage');

// Check the new password request eligibility
function checkNewPasswordRequestEligibility(req, res, next) {
    if (!req.session.recoveryTokens) return res.status(500).send(CANT_VALIDATE_RECOVERY_TOKEN);

    const recoveryToken = req.session.recoveryTokens.filter(token => token === req.body.recoveryToken);
    if (!recoveryToken || Object.keys(recoveryToken).length === 0) return res.status(403).send(INVALID_RECOVERY_TOKEN);

    const removedIndex = req.session.recoveryTokens.indexOf(recoveryToken);
    req.session.recoveryTokens.splice(removedIndex, 1);
    next();
}

// Check the credential token middleware for OTP
function checkCredentialTokenOTP(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token === null) return res.sendStatus(401);
    jwt.verify(token, process.env.APP_ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(500).send(err);
        req.user = user;
        next();
    })
}

// Check the credential token middleware
function checkCredentialToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token === null) return res.sendStatus(401);
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