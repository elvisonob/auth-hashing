const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();

const router = express.Router();

const jwtSecret = 'mysecretkey';

router.post('/register', async (req, res) => {
    const { username, password } = req.body;

    //For the auth-hash, I made a variable called hashedPassword with the 'bycrypt.hash' to hash the password
    const hashedPassword=await bcrypt.hash(password, 10)
    const createdUser = await prisma.user.create({
        data: {
            username: username,
            password: hashedPassword
        }
    });

//As per the instruction, I am sending a message which says 'User created' response when a user is registered
     if (createdUser) {
         return res.status(202).json({message:'User created'})
     }
    res.json({ data: createdUser });
});

router.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const foundUser = await prisma.user.findFirst({
        where: {
            username
        }
    });

    if (!foundUser) {
        return res.status(401).json({ error: 'Invalid username or password.' });
    }

    //Right here, I am using 'bcrypt.compare' to compare the passwords to ensure it matches.

    const passwordsMatch = await bcrypt.compare (password, foundUser.password)

    if (!passwordsMatch) {
        return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const token = jwt.sign({ username }, jwtSecret);

    res.json({ data: token });
});

module.exports = router;
