const express = require('express');
const {
  getUserValidator,
  createUserValidator,
  updateUserValidator,
  deleteUserValidator,
  changeUserPasswordValidator,
  updateLoggedUserValidator,
} = require('../utils/validators/userValidator');

const {
  getUsers,
  getUser,
  createUser,
  updateUser,
  deleteUser,
  uploadUserImage,
  resizeImage,
  changeUserPassword,
  getLoggedUserData,
  updateLoggedUserPassword,
  updateLoggedUserData,
  deleteLoggedUserData,
  protect
} = require('../services/userService');

const authService = require('../services/authService');

const router = express.Router();

//router.use(userService.protect);

 router.get('/getMe',protect, getLoggedUserData , getUser);
router.put('/changeMyPassword',protect, updateLoggedUserPassword);
router.put('/updateMe',protect, updateLoggedUserData);
router.delete('/deleteMe',protect, deleteLoggedUserData);

// Admin
router.use(authService.allowedTo('admin', 'manager'));

router.put(
  '/changePassword/:id',
  changeUserPasswordValidator,
  changeUserPassword
);

router
  .route('/')
  .get(getUsers)
  .post(uploadUserImage, resizeImage, createUserValidator, createUser);
router
  .route('/:id')
  .get(getUserValidator, getUser)
  .put(uploadUserImage, resizeImage, updateUser)
  .delete(deleteUserValidator, deleteUser);

module.exports = router;