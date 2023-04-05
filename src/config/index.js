const cors = require('cors');
const {
    DBSequelize,
    sequelizeSessionStore,
} = require('./sequelize');
const { CORSConfiguration } = require("./connection");
const cookieParser = require('cookie-parser');
const logger = require('morgan');
const session = require('express-session');
const { PROD, PREPROD } = require('../variables/general');

const AppConfig = (app, express) => {
    // Express app config
    app.locals.pluralize = require('pluralize');
    app.use(logger('dev'));
    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));

    if (process.env.APP_STATE === PROD || process.env.APP_STATE === PREPROD) app.set("trust proxy", 1);
    // CORS establishment
    app.use(cors({
        origin: CORSConfiguration(),
        credentials: true,
        optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
    }));

    // Tool to parse cookie
    app.use(cookieParser());

    // Establish session configuration
    app.use(session({
        secret: process.env.APP_SESSION_SECRET,
        name: 'OLYMPUS-SESSION',
        cookie: {
            sameSite: process.env.APP_STATE === PROD || process.env.APP_STATE === PREPROD ? 'none' : false, // in order to response to both first-party and cross-site requests
            secure: process.env.APP_STATE === PROD || process.env.APP_STATE === PREPROD, // it should set automatically to secure if is https.
            httpOnly: process.env.APP_STATE === PROD || process.env.APP_STATE === PREPROD,
            maxAge: 3 * 60 * 60 * 1000
        },
        resave: false, // don't save session if unmodified
        rolling: true, // refresh the session max age on every response 
        saveUninitialized: false,
        store: sequelizeSessionStore
    }));
    // const csrfProtection = csrf({
    //     cookie: false,
    // });

    // Global Middleware
    app.use((err, req, res, next) => {
        res.status(500).send("Something went wrong!");
    });
    // app.use(csrfProtection);

    return app;
}

module.exports = {
    AppConfig,
    db: DBSequelize
}