const User = require('../models/User');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { promisify } = require('util');
const sendEmail = require('../utils/email'); // You'll need to create this utility
const cloudinary = require('../config/cloudinary');
const cookieParser = require('cookie-parser');

const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);

  // Create cookie options
  const cookieOptions = {
    expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    httpOnly: true // Cannot be accessed or modified by browser
  };

  // If in production, make cookie secure (only sent on HTTPS)
  if (process.env.NODE_ENV === 'production') {
    cookieOptions.secure = true;
  }

  // Send cookie
  res.cookie('jwt', token, cookieOptions);

  res.status(statusCode).json({
    status: 'success',
    data: {
      user
    }
  });
};

exports.signup = async (req, res) => {
  try {
    const newUser = await User.create({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password,
      passwordConfirm: req.body.passwordConfirm
    });

    createSendToken(newUser, 201, res);
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide email and password'
      });
    }

    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.correctPassword(password, user.password))) {
      return res.status(401).json({
        status: 'fail',
        message: 'Incorrect email or password'
      });
    }

    createSendToken(user, 200, res);
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.isAuthenticated = async (req, res) => {
  try {
    // 1) Get token from cookies
    const token = req.cookies.jwt;

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        isAuthenticated: false,
        message: 'No token found'
      });
    }

    // 2) Verify token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // 3) Check if user still exists
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        status: 'fail',
        isAuthenticated: false,
        message: 'User no longer exists'
      });
    }

    // If we've made it this far, the user is authenticated
    res.status(200).json({
      status: 'success',
      isAuthenticated: true,
      data: {
        userId: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      isAuthenticated: false,
      message: 'Invalid token or token expired'
    });
  }
};

exports.logout = (req, res) => {
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true
  });
  
  res.status(200).json({ status: 'success' });
};

exports.forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'There is no user with that email address'
      });
    }

    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/users/resetPassword/${resetToken}`;
    const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

    try {
      await sendEmail({
        email: user.email,
        subject: 'Your password reset token (valid for 10 min)',
        message
      });

      res.status(200).json({
        status: 'success',
        message: 'Token sent to email!'
      });
    } catch (err) {
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save({ validateBeforeSave: false });

      return res.status(500).json({
        status: 'fail',
        message: 'There was an error sending the email. Try again later!'
      });
    }
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const hashedToken = crypto
      .createHash('sha256')
      .update(req.params.token)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({
        status: 'fail',
        message: 'Token is invalid or has expired'
      });
    }

    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    const token = signToken(user._id);

    res.status(200).json({
      status: 'success',
      token
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.getProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.protect = async (req, res, next) => {
  try {
    // 1) Get token from cookies
    const token = req.cookies.jwt;

    if (!token) {
      return res.status(401).json({
        status: 'fail',
        message: 'You are not logged in! Please log in to get access.'
      });
    }

    // 2) Verify token
    const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    // 3) Check if user still exists
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({
        status: 'fail',
        message: 'The user belonging to this token no longer exists.'
      });
    }

    // GRANT ACCESS TO PROTECTED ROUTE
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({
      status: 'fail',
      message: 'Invalid token or token expired'
    });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const updates = {
      name: req.body.name
    };

    // Handle profile photo upload
    if (req.file) {
      // Delete old image from cloudinary if exists
      if (req.user.cloudinary_id) {
        await cloudinary.uploader.destroy(req.user.cloudinary_id);
      }

      // Upload new image to cloudinary
      const result = await cloudinary.uploader.upload(req.file.path, {
        folder: 'profile_photos',
        width: 300,
        crop: "scale"
      });

      // Add cloudinary url and public_id to updates
      updates.profilePhoto = result.secure_url;
      updates.cloudinary_id = result.public_id;
    }

    const user = await User.findByIdAndUpdate(
      req.user._id,
      updates,
      {
        new: true,
        runValidators: true
      }
    );

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

// Add this function to update just the profile photo
exports.updateProfilePhoto = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please upload an image'
      });
    }

    const user = await User.findById(req.user._id);

    // Delete old image from cloudinary if exists
    if (user.cloudinary_id) {
      await cloudinary.uploader.destroy(user.cloudinary_id);
    }

    // Upload new image to cloudinary
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: 'profile_photos',
      width: 300,
      crop: "scale"
    });

    // Update user with new image details
    user.profilePhoto = result.secure_url;
    user.cloudinary_id = result.public_id;
    await user.save();

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};

exports.updateLocation = async (req, res) => {
  try {
    const { latitude, longitude } = req.body;

    // Validate inputs
    if (!latitude || !longitude) {
      return res.status(400).json({
        status: 'fail',
        message: 'Please provide both latitude and longitude'
      });
    }

    // Ensure latitude and longitude are valid numbers
    const lat = parseFloat(latitude);
    const lng = parseFloat(longitude);

    if (isNaN(lat) || isNaN(lng)) {
      return res.status(400).json({
        status: 'fail',
        message: 'Latitude and longitude must be valid numbers'
      });
    }

    // Update user location
    const user = await User.findByIdAndUpdate(
      req.user._id,
      { latitude: lat, longitude: lng },
      {
        new: true,
        runValidators: true
      }
    );

    if (!user) {
      return res.status(404).json({
        status: 'fail',
        message: 'User not found'
      });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(400).json({
      status: 'fail',
      message: err.message
    });
  }
};
