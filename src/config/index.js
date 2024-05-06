const cors = require("cors");
const { CORSConfiguration } = require("./connection");
const cookieParser = require("cookie-parser");
const logger = require("morgan");
const session = require("express-session");
const fs = require("fs");
const http = require("http");
const https = require("httpolyglot");
const { PROD, PREPROD } = require("../variables/general");
const {
  db,
  sessionStore,
} = require("forefront-polus/src/config/index");

// FIXME: There is request leak for the session store flow
// remove all the session store from all service except olympus
// to prevent all service session check by simultaneously
const AppConfig = (app, express) => {
  // env
  const APP_STATE = process.env.APP_STATE;
  const APP_ENABLE_LOCAL_HTTPS =
    process.env.APP_ENABLE_LOCAL_HTTPS;
  const APP_CERT_PATH = process.env.APP_CERT_PATH;
  const APP_KEY_PATH = process.env.APP_KEY_PATH;

  // Express app config
  app.locals.pluralize = require("pluralize");
  app.use(logger("dev"));
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  if (APP_STATE === PROD || APP_STATE === PREPROD)
    app.set("trust proxy", 1);

  // CORS establishment
  app.use(
    cors({
      origin: CORSConfiguration(),
      credentials: true,
      optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
    })
  );

  // Tool to parse cookie
  app.use(cookieParser());

  // Establish session configuration
  app.use(
    session({
      secret: process.env.APP_SESSION_SECRET,
      name: "FOREFRONT-SESSION",
      cookie: {
        sameSite:
          APP_STATE === PROD || APP_STATE === PREPROD
            ? "none"
            : false, // in order to response to both first-party and cross-site requests
        secure: APP_STATE === PROD || APP_STATE === PREPROD, // it should set automatically to secure if is https.
        httpOnly:
          APP_STATE === PROD || APP_STATE === PREPROD,
        maxAge: 24 * 60 * 60 * 1000,
      },
      proxy: true, // if you do SSL outside of node.
      resave: false, // don't save session if unmodified
      rolling: true, // refresh the session max age on every response
      saveUninitialized: false,
      store: sessionStore,
    })
  );

  // Initialize HTTP/HTTPS server
  // SSL cert for HTTPS access
  // (this is for test purposes and will not be used on production app)
  let server = http.createServer(app);
  if (APP_ENABLE_LOCAL_HTTPS) {
    const options = {
      key: fs.readFileSync(APP_KEY_PATH, "utf-8"),
      cert: fs.readFileSync(APP_CERT_PATH, "utf-8"),
    };
    server = https.createServer(options, app);
  }
  return { server, app };
};

module.exports = {
  AppConfig,
  db,
  sessionStore,
};
