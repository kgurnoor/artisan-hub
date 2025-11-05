import asyncHandler from 'express-async-handler';
import jwt from 'jsonwebtoken';
import User from '../models/user.js';

const protect = asyncHandler(async (req, res, next) => {
  let token = req.headers.authorization?.startsWith('Bearer')
    ? req.headers.authorization.split(' ')[1]
    : null;

  if (!token) {
    res.status(401);
    throw new Error('No token, authorization denied');
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');
    next();
  } catch (error) {
    console.log('JWT Error:', error.message);
    res.status(401);
    throw new Error('Token Failed, Not Authorized');
  }
});

const admin = (req, res, next) => {
  if (req.user?.isAdmin) next();
  else {
    res.status(403);
    throw new Error('Not authorized as admin');
  }
};

export { protect, admin };
