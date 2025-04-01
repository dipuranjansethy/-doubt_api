const express = require('express');
const userController = require('../controllers/userController');
const upload = require('../middleware/multer');

const router = express.Router();

router.post('/signup', userController.signup);
router.post('/login', userController.login);
router.get('/logout', userController.logout);
router.post('/forgotPassword', userController.forgotPassword);
router.patch('/resetPassword/:token', userController.resetPassword);
router.get('/profile', userController.protect, userController.getProfile);
router.get('/is-authenticated', userController.isAuthenticated);
router.patch(
  '/updateLocation',
  userController.protect,
  userController.updateLocation
);
router.patch(
  '/updateProfile',
  userController.protect,
  upload.single('profilePhoto'),
  userController.updateProfile
);

router.patch(
  '/updateProfilePhoto',
  userController.protect,
  upload.single('profilePhoto'),
  userController.updateProfilePhoto
);

module.exports = router;
