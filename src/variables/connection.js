const APP_ORIGIN = process.env.APP_ORIGIN.split(" ") || [
  "http://localhost:3000",
];

module.exports = {
  ALLOW_LIST: APP_ORIGIN,
};
