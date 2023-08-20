const { Sequelize } = require("sequelize");
const session = require("express-session");
const SessionStore = require("express-session-sequelize")(
  session.Store
);
const {
  DB_HOST,
  DB_PORT,
  DB_NAME,
  DB_USERNAME,
  DB_PASSWORD,
  DBSSLConnectionConfiguration,
} = require("./connection");

const InitDBSequelize = () => {
  const DBConnectionString = new Sequelize(
    DB_NAME,
    DB_USERNAME,
    DB_PASSWORD,
    {
      host: DB_HOST,
      port: DB_PORT,
      dialect: "mysql",
      logging: console.log,
      omitNull: false,
      dialectOptions: {
        ssl: DBSSLConnectionConfiguration(),
      },
      pool: {
        max: 20,
        min: 0,
        acquire: 60000,
        idle: 10000,
      },
      // The retry config if Deadlock Happened
      retry: {
        match: [/Deadlock/i],
        max: 3, // Maximum rety 3 times
        backoffBase: 1000, // Initial backoff duration in ms. Default: 100,
        backoffExponent: 1.5, // Exponent to increase backoff each try. Default: 1.1
      },
    }
  );

  DBConnectionString.authenticate()
    .then(() => {
      console.log(
        "Connection has been established successfully."
      );
    })
    .catch((error) => {
      console.error(
        "Unable to connect to the database:",
        error
      );
    });

  return DBConnectionString;
};

// Init the database
const DBSequelize = InitDBSequelize();
// Init the session store with the successfully established db
const sequelizeSessionStore = new SessionStore({
  db: DBSequelize,
});

module.exports = {
  DBSequelize,
  sequelizeSessionStore,
};
