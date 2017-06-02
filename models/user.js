const mongoose = require('mongoose');
const bcrypt = require('bcryptjs')
mongoose.connect('mongodb://localhost/nodeauth');

const db = mongoose.connection;

// User Schema
var UserSchema = mongoose.Schema({
    username: {
        type: String,
        index: true
    },
    password: {
        type: String
    },
    email: {
        type: String
    },
    name: {
        type: String
    },
    profileimage: {
        type: String
    }
});

const User = module.exports = mongoose.model('User', UserSchema);

module.exports.getUserById = (id, callback) => {
    User.findById(id, callback);
}

module.exports.getUserByUsername = (username, callback) => {
    let query = {username};
    User.findOne(query, callback);
}

module.exports.comparePassword = (candidatePassword, hash, callback) => {
    bcrypt.compare(candidatePassword, hash, (err, isMatch) => {
        callback(null, isMatch);
    });
}

module.exports.createUser = (newUser, callback) => {
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
            newUser.password = hash;
            newUser.save(callback);
        });
    });
}