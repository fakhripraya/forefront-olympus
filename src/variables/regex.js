const EMAIL_REGEX =
  /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{1,}))$/g;
const PASSWORD_REGEX =
  /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/g;
const PHONE_REGEX =
  /^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,8}$/g;
const KTP_REGEX = /^\+?[1-9][0-9]{7,14}$/g;
const USERNAME_REGEX = /^.{8,}$/g;
// TODO: Regex name must contain only alphabet
//const NAME_REGEX = /^[a-z] [A-Z]*$/g;

module.exports = {
  USERNAME_REGEX,
  EMAIL_REGEX,
  PHONE_REGEX,
  KTP_REGEX,
  PASSWORD_REGEX,
  //NAME_REGEX
};
