const express = require('express');
const router = express.Router();
const multer = require('multer');
const upload = multer({ 'dest': './uploads' });
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const User = require('../models/user');

router.get('/register', (req, res) => {
    res.render('register', { title: 'Register' });
});

router.get('/login', (req, res) => {
    res.render('login', { title: 'Login' });
});

router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success', 'You are now logout');
    res.redirect('/users/login');
});

router.post('/login',
    passport.authenticate('local', { failureRedirect: '/users/login', failureFlash: 'Invalid username or password' }),
    (req, res) => {
        req.flash('success', 'You are now logged in');
        res.redirect('/');
    }
);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.getUserById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new LocalStrategy((username, password, done) => {
    User.getUserByUsername(username, (err, user) => {
        if (err) throw err;

        if (!user) {
            return done(null, false, { message: 'Unknown User' });
        }

        User.comparePassword(password, user.password, (err, isMatch) => {
            if (err) return done(err);

            if (isMatch) {
                return done(null, user);
            } else {
                return done(null, false, { message: 'Invalid password' });
            }
        })
    });
}));



router.post('/register', upload.single('profileimage'), (req, res) => {
    const { name, email, username, password, password2, profileimage } = req.body;

    //Form Vaildator
    req.checkBody('name', 'Name field is required').notEmpty();
    req.checkBody('email', 'Email field is required').notEmpty();
    req.checkBody('email', 'Email field is not valid').isEmail();
    req.checkBody('username', 'Username field is required').notEmpty();
    req.checkBody('password', 'Password field is required').notEmpty();
    req.checkBody('password2', 'Passwords do not match').equals(password2);

    //Check Errors
    let errors = req.validationErrors();

    if (errors) {
        res.render('register', {
            errors: errors
        })
    } else {
        User.createUser(new User({ name, email, username, password, profileimage }));

        req.flash('success', 'You are now registered and can login');
        res.location('/');
        res.redirect('/');
    }
});

module.exports = router;
