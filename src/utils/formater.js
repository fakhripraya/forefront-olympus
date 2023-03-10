const {
    EMAIL_REGEX,
    PHONE_REGEX,
    KTP_REGEX
} = require("../variables/regex");

function validateUserPhoneNumber(phoneNumber) {
    const resultPhoneNumber = `${phoneNumber}`.match(PHONE_REGEX);
    return resultPhoneNumber;
}
function validateKTP(ktp) {
    const resultKTP = `${ktp}`.match(KTP_REGEX);
    return resultKTP;
}

function validateEmail(email) {
    const resultEmail = `${email}`.match(EMAIL_REGEX);
    return resultEmail;
}

module.exports = {
    validateUserPhoneNumber,
    validateKTP,
    validateEmail
}
