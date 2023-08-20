const {
  EMAIL_REGEX,
  PHONE_REGEX,
  KTP_REGEX,
  PASSWORD_REGEX,
  USERNAME_REGEX,
} = require("../variables/regex");

function validateUserPhoneNumber(phoneNumber) {
  const result = `${phoneNumber}`.match(PHONE_REGEX);
  return result;
}
function validateKTP(ktp) {
  const result = `${ktp}`.match(KTP_REGEX);
  return result;
}

function validateUsername(username) {
  const result = `${username}`.match(USERNAME_REGEX);
  return result;
}

function validateEmail(email) {
  const result = `${email}`.match(EMAIL_REGEX);
  return result;
}

function validatePassword(password) {
  const result = `${password}`.match(PASSWORD_REGEX);
  return result;
}

module.exports = {
  validateUsername,
  validateUserPhoneNumber,
  validateKTP,
  validateEmail,
  validatePassword,
};
