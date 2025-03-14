const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { signupSchema, loginSchema } = require("../validation/authValidation");
const User = require("../models/User");

const router = express.Router();

// @route    POST /api/auth/signup
// @desc     Register new user
router.post('/signup', async(req, res) => {
    try {
        const validatedData = signupSchema.parse(req.body);
        const { firstName, lastName, email, password } = validatedData;

        // Check if user already exists
        let user = await User.findOne({email});
        if(user) return res.status(400).json({
            msg : "User already exists"
        })

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({firstName, lastName, email, password : hashedPassword,avatar : `http://api.dicebear.com/5.x/initials/svg?seed=${firstName}%20${lastName}`
        });
        await user.save();

        const token = jwt.sign({
            id : user.id
        }, process.env.JWT_SECRET, { expiresIn: "7d" });
        res.json({
            token, user : {
                id : user.id, firstName, lastName, email
            }
        });
    } catch (error) {
        return res.status(400).json({
            msg: error.errors || "Invalid data" 
        })
    }
})

// @route    POST /api/auth/login
// @desc     Login user
router.post('/login', async(req, res) => {
    try {
        const validatedData = loginSchema.parse(req.body);
        const {email, password} = validatedData;

        let user = await User.findOne({email});
        if(!user) {
            return res.status(400).json({
                msg : "Invalid credentials"
            })
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch) {
            return res.status(400).json({
                msg : "Invalid credentials"
            })
        }

        const token = jwt.sign({
            id : user.id
        }, process.env.JWT_SECRET, { expiresIn: "7d" });
        res.json({
            token, user : {
                id : user.id, firstName : user.firstName, lastName : user.lastName, email : user.email
            }
        });
    } catch(error) {
        return res.status(400).json({
            msg: error.errors || "Invalid data"
        })
    }
})

module.exports = router;