// GENERALS ERRORS
const UNIDENTIFIED_ERROR = "Something went wrong, please contact the support if you found this error !";

// CREDENTIALS ERRORS
const USER_HAS_ALREADY_BEEN_CREATED = "User has already been created";
const EMAIL_HAS_ALREADY_BEEN_USED = "Email has already been used";
const INVALID_USERNAME = "Please input the valid username \n\n 1. Username need to at least contains 8 or more characters";
const INVALID_EMAIL = "Please input the valid email \n\n 1. Email must follow the standard email pattern";
const INVALID_KTP = "Please input the valid KTP ID";
const INVALID_PHONE_NUMBER = "Please input the valid phone number";
const INVALID_PASSWORD = "Please input the valid password \n\n 1.Password at least consist of 8 characters \n\n 2.Password at least has one uppercase letter \n\n 3.Password at least has one lowercase letter \n\n 4.Password at least has one number \n\n 5.Password at least has one of these special characters (@$!%*?&)";
const USER_UNAUTHORIZED = "User unauthorized";
const USER_ACCESS_FORBIDDEN = "User access forbidden";
const USER_NOT_FOUND = "User not found";
const WRONG_PASSWORD_INPUT = "Please input the right password";
const USER_NOT_VERIFY = "Please verify first";
const INVALID_RECOVERY_TOKEN = "Invalid recovery token";
const UNDEFINED_QUERY_PARAM = "Can't fetch query param value.";

// OTP
const PLEASE_VERIFY_OTP = "PLEASE_VERIFY_OTP";
const OTP_EXPIRED = "Your OTP has expired please re-send the OTP";
const OTP_UNMATCH = "Invalid OTP input";
const SESSION_TOKEN_NOT_FOUND = "Session token not found or might be expired";

// INTERNAL ERRORS
const CANT_VALIDATE_RECOVERY_TOKEN = "Can't validate recovery token or the token might have been used. Please request the password recovery email again";
const INTERNAL_ERROR_CANT_COMMUNICATE = "INTERNAL ERROR: Can't communicate with the other services.";

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
    INVALID_RECOVERY_TOKEN,
    USER_NOT_VERIFY,
    PLEASE_VERIFY_OTP,
    OTP_EXPIRED,
    OTP_UNMATCH,
    SESSION_TOKEN_NOT_FOUND,
    CANT_VALIDATE_RECOVERY_TOKEN,
    INTERNAL_ERROR_CANT_COMMUNICATE,
    UNDEFINED_QUERY_PARAM
}