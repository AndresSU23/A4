const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
require('dotenv').config();
let Schema = mongoose.Schema;

let userSchema = new Schema({
    userName: {
        type: String,
        unique: true,
    },
    password: String,
    email: String,
    loginHistory: [{
        dateTime: Date,
        userAgent: String
    }]
});
let User;

function initialize() {
    return new Promise(function (resolve, reject) {
        let db = mongoose.createConnection(process.env.MONGODB);

        db.on('error', (err)=>{
            reject(err); // reject the promise with the provided error
        });
        db.once('open', ()=>{
            User = db.model("users", userSchema);
            resolve();
        });
    });
}

function registerUser(userData) {
    return new Promise((resolve, reject) => {
        if (userData.password !== userData.password2) {
            return reject("Passwords do not match");
        }

        // Hash the password
        bcrypt.hash(userData.password, 10)
            .then(hash => {
                // Replace userData.password with the hashed password
                userData.password = hash;

                // Create a new User instance with the updated userData
                let newUser = new User(userData);

                // Save the user to the database
                newUser.save()
                    .then(() => {
                        resolve();
                    })
                    .catch(err => {
                        if (err.code === 11000) {
                            reject("User Name already taken");
                        } else {
                            reject(`There was an error creating the user: ${err}`);
                        }
                    });
            })
            .catch(err => {
                // If there's an error during password hashing, reject with a specific message
                reject("There was an error encrypting the password");
            });
    });
}

function checkUser(userData) {
    return new Promise((resolve, reject) => {
        // Find user by userName
        User.find({ userName: userData.userName })
            .then(users => {
                // Check if the user was found
                if (users.length === 0) {
                    return reject(`Unable to find user: ${userData.userName}`);
                }

                // Get the first user found (there should only be one)
                let user = users[0];

                // Compare the entered password with the hashed password from the database
                bcrypt.compare(userData.password, user.password)
                    .then(result => {
                        if (!result) {
                            return reject(`Incorrect Password for user: ${userData.userName}`);
                        }

                        // If passwords match, update login history
                        if (user.loginHistory.length === 8) {
                            user.loginHistory.pop();
                        }

                        user.loginHistory.unshift({
                            dateTime: (new Date()).toString(),
                            userAgent: userData.userAgent
                        });

                        // Update user login history in the database
                        User.updateOne({ userName: user.userName }, { $set: { loginHistory: user.loginHistory } })
                            .then(() => {
                                resolve(user);
                            })
                            .catch(err => {
                                reject(`There was an error verifying the user: ${err}`);
                            });
                    })
                    .catch(err => {
                        // Handle error during password comparison
                        reject(`There was an error verifying the user: ${err}`);
                    });
            })
            .catch(() => {
                // Handle error during user search
                reject(`Unable to find user: ${userData.userName}`);
            });
    });
}

module.exports = { initialize, checkUser, registerUser }

