const express = require('express');
const verifyToken = require('../middlewares/authMiddleware');
const User = require('../models/User');

const router = express.Router();

// Protected Route: Get User Profile
router.get('/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("-password");

        if(!user) {
            return res.status(404).json({ msg: "User not found" });
        }

        res.json(user);
    } catch(err) {
        console.error(err.message);
        res.status(500).json({ msg: "Server error" });
    }
})

module.exports = router;