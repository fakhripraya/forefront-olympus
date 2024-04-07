require("dotenv").config();
const express = require("express");
const {
  InitCredentialRoute,
} = require("./src/routes/credentials");
const { InitUserRoute } = require("./src/routes/user");
const { defaultRoute } = require("./src/routes/default");
const { AppConfig } = require("./src/config");
const expressApp = express();

// Init App configurations
const { server, app } = AppConfig(expressApp, express);

// Init Routes
defaultRoute(app);
InitCredentialRoute(app);
InitUserRoute(app);

const port = process.env.PORT || 8001;
server.listen(port, () => {
  console.log(`Server is up and running on ${port} ...`);
});
