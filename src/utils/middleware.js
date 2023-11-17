const jwt = require("jsonwebtoken");
const {
  PLEASE_VERIFY_OTP,
  INVALID_RECOVERY_TOKEN,
  CANT_VALIDATE_RECOVERY_TOKEN,
  SESSION_TOKEN_NOT_FOUND,
  USER_UNAUTHORIZED,
} = require("../variables/responseMessage");
const { sessionStore } = require("../config/index");
const { X_SID } = require("../variables/general");

// Check the new password request eligibility
async function checkNewPasswordRequestEligibility(
  req,
  res,
  next
) {
  if (!req.headers[X_SID])
    return res.status(401).send(SESSION_TOKEN_NOT_FOUND);

  await sessionStore.get(
    req.headers[X_SID],
    (err, result) => {
      if (err)
        return res
          .status(401)
          .send(SESSION_TOKEN_NOT_FOUND);

      if (!result.recoveryInfo)
        return res
          .status(403)
          .send(CANT_VALIDATE_RECOVERY_TOKEN);

      if (
        result.recoveryInfo.token !== req.body.recoveryToken
      )
        return res.status(403).send(INVALID_RECOVERY_TOKEN);

      req.user = {
        session: result,
      };
      next();
    }
  );
}

// Check the credential token middleware for OTP
async function checkCredentialTokenOTP(req, res, next) {
  if (!req.headers[X_SID])
    return res.status(401).send(SESSION_TOKEN_NOT_FOUND);

  await sessionStore.get(
    req.headers[X_SID],
    (err, result) => {
      if (err)
        return res
          .status(401)
          .send(SESSION_TOKEN_NOT_FOUND);

      // Check the JWT in the header
      const authHeader = req.headers["authorization"];
      const token = authHeader && authHeader.split(" ")[1];
      if (token === null)
        return res.status(401).send(USER_UNAUTHORIZED);

      // Verify JWT access token
      jwt.verify(
        token,
        process.env.APP_ACCESS_TOKEN_SECRET,
        (err, user) => {
          if (err) return res.status(500).send(err);
          req.user = user;
          req.user.session = result;
          next();
        }
      );
    }
  );
}

// Check the credential token middleware
async function checkCredentialToken(req, res, next) {
  //console.log(req.user.session);
  console.log(req.headers[X_SID]);
  if (!req.headers[X_SID])
    return res.status(401).send(SESSION_TOKEN_NOT_FOUND);

  await sessionStore.get(
    req.headers[X_SID],
    (err, result) => {
      if (err)
        return res
          .status(401)
          .send(SESSION_TOKEN_NOT_FOUND);

      // Check the JWT in the header
      const authHeader = req.headers["authorization"];
      const token = authHeader && authHeader.split(" ")[1];
      if (token === null)
        return res.status(401).send(USER_UNAUTHORIZED);

      // Verify JWT access token
      jwt.verify(
        token,
        process.env.APP_ACCESS_TOKEN_SECRET,
        (err, user) => {
          if (err) return res.status(500).send(err);
          if (!user.OTPVerified)
            return res.status(403).send(PLEASE_VERIFY_OTP);
          req.user = user;
          req.user.session = result;
          next();
        }
      );
    }
  );
}

function handleCSRFToken(req, res, next) {
  //TODO: handle csrf later
  res.locals.csrfToken = req.csrfToken();
  next();
}

module.exports = {
  checkNewPasswordRequestEligibility,
  checkCredentialTokenOTP,
  checkCredentialToken,
  handleCSRFToken,
};
