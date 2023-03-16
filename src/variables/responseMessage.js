// GENERALS ERRORS
const UNIDENTIFIED_ERROR = "Something went wrong, please contact the support if you found this error !";

// CREDENTIALS ERRORS
const USER_HAS_ALREADY_BEEN_CREATED = "User has already been created";
const EMAIL_HAS_ALREADY_BEEN_USED = "Email has already been used";
const INVALID_USERNAME = "Please input the valid username \n\n 1. Username need to at least contains 8 or more characters";
const INVALID_EMAIL = "Please input the valid email \n\n 1. Email must follow the standard email pattern";
const INVALID_KTP = "Please input the valid KTP ID";
const INVALID_PHONE_NUMBER = "Please input the valid phone number";
const INVALID_PASSWORD = "Please input the valid password \n\n 1.Password at least consist of 8 characters Password at least has one uppercase letter \n\n 2.Password at least has one lowercase letter \n\n 3.Password at least has one number \n\n 4.Password at least has one special character";
const USER_UNAUTHORIZED = "User unauthorized";
const USER_ACCESS_FORBIDDEN = "User access forbidden";
const USER_NOT_FOUND = "User not found";
const WRONG_PASSWORD_INPUT = "Please input the right password";
const USER_NOT_VERIFY = "Please verify first";

// OTP
const PLEASE_VERIFY_OTP = "PLEASE_VERIFY_OTP";
const OTP_EXPIRED = "Your OTP has expired please re-send the OTP";
const OTP_UNMATCH = "Invalid OTP input";

module.exports = {
    USER_HAS_ALREADY_BEEN_CREATED,
    EMAIL_HAS_ALREADY_BEEN_USED,
    INVALID_USERNAME,
    INVALID_EMAIL,
    INVALID_KTP,
    INVALID_PHONE_NUMBER,
    INVALID_PASSWORD,
    USER_UNAUTHORIZED,
    USER_ACCESS_FORBIDDEN,
    USER_NOT_FOUND,
    WRONG_PASSWORD_INPUT,
    UNIDENTIFIED_ERROR,
    USER_NOT_VERIFY,
    PLEASE_VERIFY_OTP,
    OTP_EXPIRED,
    OTP_UNMATCH
}