const APP_ORIGIN = process.env.APP_ORIGIN.split(' ') || ["http://localhost:3000"];

console.log("APP ORIGINS: ");
console.log(APP_ORIGIN);
module.exports = {
    ALLOW_LIST: APP_ORIGIN
}