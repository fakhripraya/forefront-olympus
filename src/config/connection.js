const { ALLOW_LIST } = require("../variables/connection");

const CORSConfiguration = () => {
  return ALLOW_LIST;
};

module.exports = {
  CORSConfiguration,
};
