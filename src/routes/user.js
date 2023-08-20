const {
  UNIDENTIFIED_ERROR,
} = require("../variables/responseMessage");

const InitUserRoute = (app) => {
  // GET Method
  // Route: /{version}/user/update
  // Get all user related data
  app.get(
    `/v${process.env.APP_MAJOR_VERSION}/user/update`,
    (req, res) => {
      // check query param availability
      if (!req.body)
        return res.status(400).send(UNIDENTIFIED_ERROR);
    }
  );
};

module.exports = {
  InitUserRoute,
};
