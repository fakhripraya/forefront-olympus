const { checkCredentialToken } = require("../utils/middleware");
const { USER_UNAUTHORIZED } = require("../variables/responseMessage");

const defaultRoute = (app) => {
    app.get(`/v${process.env.APP_MAJOR_VERSION}/`, checkCredentialToken, (req, res) => {
        if (!req.user) return res.send(USER_UNAUTHORIZED).status(401);
        else return res.send(req.user).status(201);
    });
}

module.exports = {
    defaultRoute
}