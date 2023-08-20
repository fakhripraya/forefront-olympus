const { DataTypes, UUIDV4 } = require("sequelize");
const { db } = require("../../config");
const { USER } = require("../../variables/general");

const MasterUser = db.define(
  "MasterUser",
  {
    id: {
      primaryKey: true,
      allowNull: false,
      unique: true,
      type: DataTypes.UUID,
      defaultValue: UUIDV4,
    },
    googleId: {
      allowNull: true,
      type: DataTypes.STRING,
    },
    facebookId: {
      allowNull: true,
      type: DataTypes.STRING,
    },
    username: {
      allowNull: false,
      type: DataTypes.STRING,
    },
    fullName: {
      allowNull: true,
      type: DataTypes.STRING,
    },
    phoneNumber: {
      allowNull: true,
      type: DataTypes.STRING,
    },
    dateOfBirth: {
      allowNull: true,
      type: DataTypes.DATE,
    },
    profilePictureURI: {
      allowNull: true,
      type: DataTypes.STRING,
    },
    KTPNumber: {
      allowNull: true,
      type: DataTypes.STRING,
    },
    email: {
      allowNull: false,
      type: DataTypes.STRING,
    },
    roles: {
      allowNull: false,
      type: DataTypes.JSON,
      defaultValue: `[${USER}]`,
    },
    hashedPassword: {
      allowNull: false,
      type: DataTypes.BLOB,
    },
    salt: {
      allowNull: false,
      type: DataTypes.BLOB,
    },
  },
  {
    indexes: [{ unique: true, fields: ["username"] }],
    paranoid: true,
    deletedAt: "destroyTime",
    tableName: "master_user",
  }
);

module.exports = { MasterUser };
