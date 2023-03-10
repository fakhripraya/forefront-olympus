const EMAIL_REGEX = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{1,}))$/g;
const PHONE_REGEX = /^[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,8}$/g;
const KTP_REGEX = /^\+?[1-9][0-9]{7,14}$/g;
// TODO: Regex username match contain numeric, symbol, and alphabet
//const USERNAME_REGEX = /^[a-z] [A-Z]*$/g;
// TODO: Regex name must contain only alphabet
//const NAME_REGEX = /^[a-z] [A-Z]*$/g;

module.exports = {
    EMAIL_REGEX,
    PHONE_REGEX,
    KTP_REGEX,
    //USERNAME_REGEX,
    //NAME_REGEX
}