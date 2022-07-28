require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
const server = process.env.PORT || 3000;

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.set("view engine", "ejs");

app.use(
	session({
		secret: "My Small Secrete.",
		resave: false,
		saveUninitialized: false,
		cookie: {},
	})
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(
	`mongodb+srv://admin-eniola:${process.env.PASSWORD}@cluster0.velr6at.mongodb.net/userDB`
);

const userSchema = new mongoose.Schema({
	email: String,
	password: String,
	googleId: String,
	facebookId: String,
	secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
	done(null, user);
});

passport.deserializeUser(function (user, done) {
	done(null, user);
});

passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.CLIENT_ID,
			clientSecret: process.env.CLIENT_SECRET,
			callbackURL:
				"https://agile-caverns-55089.herokuapp.com/auth/google/secrets",
		},
		(accessToken, refreshToken, profile, cb) => {
			// console.log(profile);
			User.findOrCreate({ googleId: profile.id }, (err, user) => {
				return cb(err, user);
			});
		}
	)
);

passport.use(
	new FacebookStrategy(
		{
			clientID: process.env.APP_ID,
			clientSecret: process.env.APP_SECRET,
			callbackURL:
				"https://agile-caverns-55089.herokuapp.com/auth/facebook/secrets",
		},
		(accessToken, refreshToken, profile, cb) => {
			// console.log(profile);
			User.findOrCreate({ facebookId: profile.id }, (err, user) => {
				return cb(err, user);
			});
		}
	)
);

app.get("/", (req, res) => {
	res.render("home");
});

app.get(
	"/auth/google",
	passport.authenticate("google", { scope: ["profile"] })
);

app.get(
	"/auth/google/secrets",
	passport.authenticate("google", { failureRedirect: "/login" }),
	function (req, res) {
		// Successful authentication, redirect secrets.
		res.redirect("/secrets");
	}
);

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
	"/auth/facebook/secrets",
	passport.authenticate("facebook", { failureRedirect: "/login" }),
	(req, res) => {
		// Successful authentication, redirect home.
		res.redirect("/secrets");
	}
);

app.get("/login", (req, res) => {
	res.render("login");
});

app.get("/register", (req, res) => {
	res.render("register");
});

app.get("/secrets", (req, res) => {
	User.find({ secret: { $ne: null } }, (err, foundUsers) => {
		if (err) {
			console.log(err);
		} else {
			if (foundUsers) {
				res.render("secrets", { userWithSecrets: foundUsers });
			}
		}
	});
});

app.get("/submit", (req, res) => {
	if (req.isAuthenticated()) {
		res.render("submit");
	} else {
		res.redirect("/login");
	}
});

app.post("/submit", (req, res) => {
	const submitedSecret = req.body.secret;
	console.log(submitedSecret);
	console.log(req.user._id);

	User.findById(req.user._id, (err, foundUser) => {
		if (err) {
			console.log(err);
		} else {
			if (foundUser) {
				console.log(foundUser);
				foundUser.secret = submitedSecret;
				foundUser.save(() => {
					res.redirect("/secrets");
				});
			}
		}
	});
});

app.get("/logout", (req, res) => {
	req.logout((err) => {
		if (err) {
			console.log();
		} else {
			res.redirect("/");
		}
	});
});

app.post("/register", (req, res) => {
	User.register(
		{ username: req.body.username },
		req.body.password,
		(err, user) => {
			if (err) {
				console.log(err);
				res.redirect("/register");
			} else {
				passport.authenticate("local")(req, res, () => {
					res.redirect("/secrets");
				});
			}
		}
	);
});

app.post("/login", (req, res) => {
	const user = new User({
		username: req.body.username,
		password: req.body.password,
	});
	req.logIn(user, (err) => {
		if (err) {
			console.log(err);
		} else {
			passport.authenticate("local")(req, res, () => {
				res.redirect("/secrets");
			});
		}
	});
});

app.listen(server, () => {
	console.log("App listening on port ", server);
});
