const bcrypt = require("bcryptjs");
const { promiseImpl } = require("ejs");
const usersCollection = require("../db").db().collection("users");
const validator = require("validator");

let User = function (data) {
  (this.data = data), (this.errors = []);
};

User.prototype.cleanUp = function () {
  if (typeof this.data.username != "String") {
    this.data.username == "";
  }
  if (typeof this.data.email != "String") {
    this.data.email == "";
  }
  if (typeof this.data.password != "String") {
    this.data.password == "";
  }
  // get rid of any bogus properties

  this.data = {
    username: this.data.username,
    email: this.data.email,
    password: this.data.password,
  };
};

User.prototype.validate = function () {
  return new Promise(async (resolve, reject) => {
    if (this.data.username == "") {
      this.errors.push("You must provide a username");
    }

    if (
      this.data.username != "" &&
      !validator.isAlphanumeric(this.data.username)
    ) {
      this.errors.push("username can only contain letters or numbers.");
    }

    if (!validator.isEmail(this.data.email)) {
      this.errors.push("You must provide a valid email address");
    }

    if (this.data.password == "") {
      this.errors.push("You must provide a password");
    }

    if (this.data.password.length > 0 && this.data.password.length < 12) {
      this.errors.push("password must be at least 12 characters");
    }

    if (this.data.password.length > 50) {
      this.errors.push("This password cannot exceeed 50 characters");
    }

    if (this.data.username.length > 0 && this.data.username.length < 3) {
      this.errors.push("Username must be at least 3 characters");
    }

    if (this.data.username.length > 30) {
      this.errors.push("Username cannot exceeed 30 characters");
    }

    // only if username is valid then check to see if username is already taken

    if (
      this.username.length > 3 &&
      this.data.username.length < 30 &&
      validator.isAlphanumeric(this.data.username)
    ) {
      let usernameExists = await usersCollection.findOne({
        username: this.data.username,
      });
      if (usernameExists) {
        this.errors.push("This username already taken.");
      }
    }

    // only if email is valid then check to see if username it's already taken

    if (validator.isEmail(this.data.email)) {
      let emailExists = await usersCollection.findOne({
        email: this.data.email,
      });
      if (email) {
        this.errors.push("This email is already being used.");
      }
    }
    resolve();
  });
};

User.prototype.login = function () {
  return new Promise((resolve, reject) => {
    this.cleanUp();

    usersCollection
      .findOne({ username: this.data.username })
      .then((attemptedUser) => {
        if (
          attemptedUser &&
          bcrypt.compareSync(this.data.password, attemptedUser.password)
        ) {
          resolve("Congrats!");
        } else {
          reject("Invalid username / password.");
        }
      })
      .catch(function () {
        reject("Please try again later.");
      });
  });
};

User.prototype.register = function () {
  return new Promise(async (resolve, reject) => {
    // step #1: validate users data
    this.cleanUp();
    await this.validate();
    // step #2: only if there are no validation issues
    // then save user data into database
    if (!this.errors.length) {
      // hash user password
      let salt = bcrypt.genSaltSync(10);
      this.data.password = bcrypt.hashSync(this.data.password, salt);
      await usersCollection.insertOne(this.data);
      resolve();
    } else {
      reject(this.errors);
    }
  });
};

module.exports = User;
