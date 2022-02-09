const router = require("express").Router();
const bcrypt = require("bcryptjs");
const { redirect } = require("express/lib/response");
const User = require("../models/User.model");
const saltRounds = 10;

//Iteration 1
router.get("/signup", (req, res, next) => {
  res.render("users/signup");
});

router.post("/signup", function (req, res, next) {
  if (!req.body.username) {
    res.send("You did not include a username");
  } else if (!req.body.password) {
    res.send("You need a password");
  }

  const salt = bcrypt.genSaltSync(saltRounds);
  const hashedPass = bcrypt.hashSync(req.body.password, salt);

  User.create({
    username: req.body.username,
    password: hashedPass,
  })
    .then((newUser) => {
      console.log("User was created", newUser);
      res.redirect("/");
    })
    .catch((err) => {
      res.send("This username is already taken");
      console.log("Something went wrong", err.errors);
    });
});

//Iteration 2
//Log In

router.get("/login", function (req, res, next) {
  res.render("users/login");
});

router.post("/login", function (req, res, next) {
  // Check if user left any field blank
  if (!req.body.username) {
    res.send("You did not include a username");
  } else if (!req.body.password) {
    res.send("You need a password");
  }
  // Check if the username is correct
  User.findOne({ username: req.body.username })
    .then((foundUser) => {
      if (!foundUser) {
        return res.send("Username not found");
      }
      // Check if the password is correct
      const match = bcrypt.compareSync(req.body.password, foundUser.password);
      // If the password doesn't match
      if (!match) {
        return res.send("Incorrect password");
      }
      // If all of the above checks pass, session can be called
      req.session.user = foundUser;
      res.render("users/profile", { user: req.session.user });
    })
    .catch((err) => {
      console.log("Something went wrong", err);
    });
});

//Log Out
router.get("/profile", function (req, res, next) {
  req.session.destroy();
  res.render("users/logout");
});

module.exports = router;
