const {
    EMAIL_REGEX,
    PHONE_REGEX,
    KTP_REGEX,
    PASSWORD_REGEX,
    USERNAME_REGEX
} = require("../variables/regex");

function validateUserPhoneNumber(phoneNumber) {
    const resultPhoneNumber = `${phoneNumber}`.match(PHONE_REGEX);
    return resultPhoneNumber;
}
function validateKTP(ktp) {
    const resultKTP = `${ktp}`.match(KTP_REGEX);
    return resultKTP;
}

function validateUsername(username) {
    const resultUsername = `${username}`.match(USERNAME_REGEX);
    return resultUsername;
}

function validateEmail(email) {
    const resultEmail = `${email}`.match(EMAIL_REGEX);
    return resultEmail;
}

function validatePassword(password) {
    const resultPassword = `${password}`.match(PASSWORD_REGEX);
    return resultPassword;
}

module.exports = {
    validateUsername,
    validateUserPhoneNumber,
    validateKTP,
    validateEmail,
    validatePassword
}
