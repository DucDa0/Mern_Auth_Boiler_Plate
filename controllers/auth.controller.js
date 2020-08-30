const User = require('../models/auth.model');
const expressJwt = require('express-jwt');
const _ = require('lodash');
const { OAuth2Client } = require('google-auth-library');
const fetch = require('node-fetch');
const { validationResult } = require('express-validator');
const jwt = require('jsonwebtoken');
const { errorHandler } = require('../helpers/dbErrorHandling');
const nodemailer = require('nodemailer');

exports.registerController = async (req, res) => {
  const { name, email, password } = req.body;
  const errors = validationResult(req);
  // *validation to req.body we will create custom validate in seconds
  if (!errors.isEmpty()) {
    const firstError = errors.array().map((error) => error.msg)[0];
    return res.status(422).json({
      error: firstError,
    });
  } else {
    const user = await User.findOne({
      email,
    });

    if (user) {
      return res.status(400).json({
        error: 'Email is already exist',
      });
    }
    //* generate token for active account
    const token = jwt.sign(
      {
        name,
        email,
        password,
      },
      process.env.JWT_ACCOUNT_ACTIVATION,
      {
        expiresIn: '1d',
      }
    );
    //* email sending
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      auth: {
        user: process.env.NODEMAILER_EMAIL,
        pass: process.env.NODEMAILER_PASS,
      },
    });
    const content = `
              <h1>Please click this link to active your account</h1>
              <p>${process.env.CLIENT_URL}/users/activate/${token}</p>
              <hr/>
              <p>This email contain sensetive information</p>
              <p>${process.env.CLIENT_URL}</p>
          `;
    const mainOptions = {
      from: process.env.NODEMAILER_EMAIL,
      to: email,
      subject: 'Account activation link',
      html: content,
    };
    transporter.sendMail(mainOptions, function (err, info) {
      if (!err) {
        return res
          .json({
            message: `An email has been sent to ${email}`,
          })
          .catch((err) => {
            return res.status(400).json({
              error: errorHandler(err),
            });
          });
      }
    });
  }
};

//* activation and save to db
exports.activationController = (req, res) => {
  const { token } = req.body;
  if (token) {
    // *verify the token is valid or not or expired
    jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, (err, decoded) => {
      if (err) {
        return res.status(401).json({
          error: 'Expired Token. Sign Up again',
        });
      } else {
        //*if valid save to db
        //*get name email, pass from token
        const { name, email, password } = jwt.decode(token);
        const user = new User({
          name,
          email,
          password,
        });
        user.save((err, user) => {
          if (err) {
            return res.status(401).json({
              error: errorHandler(err),
            });
          } else {
            return res.json({
              message: 'Actived success, you can log in now',
            });
          }
        });
      }
    });
  } else {
    return res.json({
      message: 'Error happening please try again',
    });
  }
};

exports.loginController = async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const firstError = errors.array().map((error) => error.msg)[0];
    return res.status(422).json({
      error: firstError,
    });
  } else {
    //* check if user exist
    const { email, password } = req.body;
    const user = await User.findOne({
      email,
    });
    if (!user) {
      return res.status(400).json({
        error: 'User with that email does not exist, please Sign Up',
      });
    }
    //* authenticate
    const isMatch = await user.checkPassword(password);
    if (!isMatch) {
      return res.status(400).json({
        error: 'Email or password does not match',
      });
    } else {
      //*generate token for login
      const token = user.genJwtToken();
      const { _id, name, email, role } = user;
      return res.json({
        token,
        user: {
          _id,
          name,
          email,
          role,
        },
      });
    }
  }
};
exports.requireSignin = expressJwt({
  secret: process.env.JWT_SECRET, // req.user._id
  algorithms: ['HS256'],
});

exports.adminMiddleware = (req, res, next) => {
  User.findById({
    _id: req.user._id,
  }).exec((err, user) => {
    if (err || !user) {
      return res.status(400).json({
        error: 'User not found',
      });
    }

    if (user.role !== 'admin') {
      return res.status(400).json({
        error: 'Admin resource. Access denied.',
      });
    }

    req.profile = user;
    next();
  });
};
exports.forgetController = (req, res) => {
  const { email } = req.body;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const firstError = errors.array().map((error) => error.msg)[0];
    return res.status(422).json({
      error: firstError,
    });
  } else {
    User.findOne({ email }, (err, user) => {
      if (err || !user) {
        return res.status(400).json({
          error: 'User with this email does not exist',
        });
      }
      // *if exist
      //* generate token for user with this id is valid for only 10m
      const token = jwt.sign(
        {
          _id: user._id,
        },
        process.env.JWT_RESET_PASSWORD,
        { expiresIn: '10m' }
      );

      //* email sending
      const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        auth: {
          user: process.env.NODEMAILER_EMAIL,
          pass: process.env.NODEMAILER_PASS,
        },
      });
      const content = `
                  <h1>Please Click to link to reset your password</h1>
                  <p>${process.env.CLIENT_URL}/users/password/reset/${token}</p>
                  <hr/>
                  <p>This email contain sensetive information</p>
                  <p>${process.env.CLIENT_URL}</p>
              `;
      const mainOptions = {
        from: process.env.NODEMAILER_EMAIL,
        to: email,
        subject: 'Password reset link',
        html: content,
      };
      user.updateOne(
        {
          resetPasswordLink: token,
        },
        (err, success) => {
          if (err) {
            return res.status(400).json({
              error: errorHandler(err),
            });
          } else {
            transporter.sendMail(mainOptions, function (err, info) {
              if (!err) {
                return res
                  .json({
                    message: `An email has been sent to ${email}`,
                  })
                  .catch((err) => {
                    return res.json({
                      error: errorHandler(err),
                    });
                  });
              }
            });
          }
        }
      );
    });
  }
};

exports.resetController = (req, res) => {
  const { resetPasswordLink, newPassword } = req.body;

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    const firstError = errors.array().map((error) => error.msg)[0];
    return res.status(422).json({
      error: firstError,
    });
  } else {
    if (resetPasswordLink) {
      jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function (
        err,
        decoded
      ) {
        if (err) {
          return res.status(400).json({
            error: 'Expired link. Try again',
          });
        }

        User.findOne(
          {
            resetPasswordLink,
          },
          (err, user) => {
            if (err || !user) {
              return res.status(400).json({
                error: 'Something went wrong. Try later',
              });
            }
            const updatedFields = {
              password: newPassword,
              resetPasswordLink: '',
            };

            user = _.extend(user, updatedFields);

            user.save((err, result) => {
              if (err) {
                return res.status(400).json({
                  error: 'Error resetting user password',
                });
              }
              res.json({
                message: `Reset password done! You can login with your new password`,
              });
            });
          }
        );
      });
    }
  }
};

const client = new OAuth2Client(process.env.GOOGLE_CLIENT);
exports.googleController = (req, res) => {
  const { idToken } = req.body;
  //*get token from request

  //*verify token
  client
    .verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT })
    .then((response) => {
      const { email_verified, name, email } = response.payload;
      if (email_verified) {
        User.findOne({ email }).exec((err, user) => {
          //*find if this email already exists
          //* if exists
          if (user) {
            const token = user.genJwtToken();
            const { _id, email, name, role } = user;
            //* send response to client side(react) token and userminfo
            return res.json({
              token,
              user: { _id, email, name, role },
            });
          } else {
            //*if user not exists, save in db and generate pass for it
            let newPassword = email + process.env.JWT_SECRET;
            user = new User({ name, email, password: newPassword }); //* create user with this email
            user.save((err, user) => {
              if (err) {
                return res.status(400).json({
                  error: errorHandler(err),
                });
              }
              //* if no error generate token
              const token = user.genJwtToken();
              const { _id, email, name, role } = user;
              return res.json({
                token,
                user: { _id, email, name, role },
              });
            });
          }
        });
      } else {
        //* if error
        return res.status(400).json({
          error: 'Google login failed, try again!',
        });
      }
    });
};

exports.facebookController = (req, res) => {
  const { userID, accessToken } = req.body;

  const url = `https://graph.facebook.com/v2.11/${userID}/?fields=id,name,email&access_token=${accessToken}`;

  return fetch(url, {
    method: 'GET',
  })
    .then((response) => response.json())
    .then((response) => {
      const { email, name } = response;
      User.findOne({ email }).exec((err, user) => {
        if (user) {
          const token = user.genJwtToken();
          const { _id, email, name, role } = user;
          return res.json({
            token,
            user: { _id, email, name, role },
          });
        } else {
          let newPassword = email + process.env.JWT_SECRET;
          user = new User({ name, email, password: newPassword });
          user.save((err, user) => {
            if (err) {
              return res.status(400).json({
                error: 'User signup failed with facebook',
              });
            }
            const token = user.genJwtToken();
            const { _id, email, name, role } = user;
            return res.json({
              token,
              user: { _id, email, name, role },
            });
          });
        }
      });
    })
    .catch((error) => {
      res.json({
        error: 'Facebook login failed. Try later',
      });
    });
};
