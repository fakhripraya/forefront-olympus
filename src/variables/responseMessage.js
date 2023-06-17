// GENERALS ERRORS
const UNIDENTIFIED_ERROR = "Ada yang salah ni kawan, coba kontak customer service ya biar kamu dibantuin !";

// CREDENTIALS ERRORS
const USER_HAS_ALREADY_BEEN_CREATED = "User dengan username tersebut sudah ada.";
const EMAIL_HAS_ALREADY_BEEN_USED = "Email sudah pernah digunakan.";
const INVALID_USERNAME = "Mohon input username anda dengan benar \n\n 1. Username harus mengandung 8 karakter atau lebih !";
const INVALID_EMAIL = "Mohon input email anda dengan benar \n\n 1. Email harus mengikuti pattern standard email !";
const INVALID_KTP = "Mohon input KTP anda dengan benar";
const INVALID_PHONE_NUMBER = "Mohon input nomor telepon anda dengan benar";
const INVALID_PASSWORD = "Mohon input password anda dengan benar \n\n 1.Password harus mengandung 8 karakter atau lebih ! \n\n 2.Password setidaknya mengandung 1 huruf kapital ! \n\n 3.Password setidaknya mengandung 1 huruf kecil ! \n\n 4.Password setidaknya mengandung 1 angka ! \n\n 5.Password setidaknya mengandung karakter special ! (@$!%*?&)";
const USER_UNAUTHORIZED = "User tidak terautorisasi";
const USER_ACCESS_FORBIDDEN = "User tidak ada akses";
const USER_NOT_FOUND = "User tidak ditemukan";
const WRONG_PASSWORD_INPUT = "Mohon input password anda dengan benar";
const USER_NOT_VERIFY = "Mohon verifikasi terlebih dahulu";
const INVALID_RECOVERY_TOKEN = "Recovery token salah !";
const UNDEFINED_QUERY_PARAM = "Can't fetch query param value.";

// OTP
const PLEASE_VERIFY_OTP = "PLEASE_VERIFY_OTP";
const OTP_EXPIRED = "OTP anda sudah expired, mohon request ulang OTP !";
const OTP_UNMATCH = "Input OTP salah !";
const SESSION_TOKEN_NOT_FOUND = "Session token tidak dapat ditemukan !";

// INTERNAL ERRORS
const CANT_VALIDATE_RECOVERY_TOKEN = "Recovery token tidak dapat tervalidasi, token mungkin sudah pernah digunakan. \n\n Silahkan request email recovery password lagi ya.";
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