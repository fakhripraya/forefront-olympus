const {
  checkCredentialToken,
} = require("../utils/middleware");
const {
  USER_UNAUTHORIZED,
} = require("../variables/responseMessage");

const defaultRoute = (app) => {
  app.get(`/v1/`, checkCredentialToken, (req, res) => {
    if (!req.user)
      return res.status(401).send(USER_UNAUTHORIZED);
    else return res.status(201).send(req.user);
  });
};

module.exports = {
  defaultRoute,
};
