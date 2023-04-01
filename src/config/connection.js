const { ALLOW_LIST } = require("../variables/connection");

// DATABASE
const DB_HOST = process.env.APP_DB_HOST || "localhost";
const DB_PORT = process.env.APP_DB_PORT || "3306";
const DB_NAME = process.env.APP_DB_NAME || "coolie";
const DB_USERNAME = process.env.APP_DB_USERNAME || "root";
const DB_PASSWORD = process.env.APP_DB_PASSWORD || "";

const DBSSLConnectionConfiguration = () => {
    if (DB_HOST.includes("localhost")) return false;
    else return { "rejectUnauthorized": true };
}

const CORSConfiguration = () => {
    return ALLOW_LIST
}

module.exports = {
    DB_HOST,
    DB_PORT,
    DB_NAME,
    DB_USERNAME,
    DB_PASSWORD,
    CORSConfiguration,
    DBSSLConnectionConfiguration,
}