const { db } = require("../config");
require("./user/master_user");

const InitModels = async () => {
  await db
    .sync({ alter: true, force: false })
    .then(() => {
      console.log(
        "All models has been synchronized successfully."
      );
    })
    .catch((err) => {
      console.log(err);
    })
    .finally(() => {
      db.close();
      console.log("Model initialization completed");
    });
};

module.exports = { InitModels };
