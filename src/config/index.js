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

    // CORS establishment
    app.use(cors({
        origin: CORSConfiguration(),
        credentials: true,
        optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
    }));

    // Tool to parse cookie
    app.use(cookieParser());

    console.log(process.env.APP_STATE)

    // Establish session configuration
    app.use(session({
        secret: process.env.APP_SESSION_SECRET,
        cookie: {
            secure: process.env.APP_STATE === PROD || process.env.APP_STATE === PREPROD,
            maxAge: 3 * 60 * 60 * 1000
        },
        resave: false, // don't save session if unmodified
        saveUninitialized: false, // don't create session until something stored
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