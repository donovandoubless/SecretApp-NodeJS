require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const bcrypt = require("bcrypt");

const LocalStrategy = require("passport-local").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
	session({
		secret: process.env.SECRET,
		resave: false,
		saveUninitialized: false,
	})
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.DATABASE_URL, {
	useNewUrlParser: true,
	useUnifiedTopology: true,
	useCreateIndex: true,
});

const userSchema = new mongoose.Schema({
	username: String,
	password: String,
	googleId: String,
	facebookId: String,
	secret: [String],
});

userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.findById(id, function (err, user) {
		done(err, user);
	});
});

passport.use(
	new LocalStrategy(function (username, password, done) {
		User.findOne({ username: username }, function (err, user) {
			if (err) {
				return done(err);
			}
			if (!user) {
				return done(null, false);
			}

			bcrypt.compare(password, user.password, function (err, result) {
				if (err) {
					throw err;
				}
				if (result === true) {
					return done(null, user);
				} else {
					return done(null, false);
				}
			});
		});
	})
);

passport.use(
	new GoogleStrategy(
		{
			clientID: process.env.GOOGLE_CLIENT_ID,
			clientSecret: process.env.GOOGLE_CLIENT_SECRET,
			callbackURL: process.env.GOOGLE_CALLBACK_URL,
			userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
		},
		function (accessToken, refreshToken, profile, cb) {
			User.findOrCreate({ googleId: profile.id }, function (err, user) {
				return cb(err, user);
			});
		}
	)
);

passport.use(
	new FacebookStrategy(
		{
			clientID: process.env.FACEBOOK_APP_ID,
			clientSecret: process.env.FACEBOOK_APP_SECRET,
			callbackURL: process.env.FACEBOOK_CALLBACK_URL,
			profileFields: ["id", "emails", "name"],
		},
		function (accessToken, refreshToken, profile, cb) {
			User.findOrCreate(
				{ username: profile.emails[0].value, facebookId: profile.id },
				function (err, user) {
					console.log(profile);
					return cb(err, user);
				}
			);
		}
	)
);

app.get("/", function (req, res) {
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
		res.redirect("/secrets");
	}
);

app.get(
	"/auth/facebook",
	passport.authenticate("facebook", { scope: ["email"] }),
	function (req, res) {}
);

app.get(
	"/auth/facebook/secrets",
	passport.authenticate("facebook", { failureRedirect: "/login" }),
	function (req, res) {
		res.redirect("/secrets");
	}
);

app
	.route("/login")
	.get(function (req, res) {
		res.render("login", {
			userMessage: "",
		});
	})
	.post(function (req, res, next) {
		passport.authenticate("local", function (err, user, info) {
			if (err) {
				throw err;
			}
			if (!user) {
				res.render("login", {
					userMessage: "User does not exist!",
				});
			} else {
				req.logIn(user, (err) => {
					if (err) throw err;
					res.redirect("/secrets");
				});
			}
		})(req, res, next);
	});

app
	.route("/register")
	.get(function (req, res) {
		res.render("register", {
			userMessage: "",
		});
	})
	.post(function (req, res, next) {
		if (req.body.password === req.body.checkPassword) {
			User.findOne({ username: req.body.username }, function (err, doc) {
				if (err) {
					throw err;
				}
				if (doc) {
					res.render("register", {
						userMessage:
							"Email is already registered. Please try another email or login",
					});
				}
				if (!doc) {
					const saltRounds = 10;

					bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
						const newUser = new User({
							username: req.body.username,
							password: hash,
						});

						newUser.save();
						res.redirect("/login");
					});
				}
			});
		} else {
			res.render("register", {
				userMessage:
					"Value entered for password/confim password does not match! Please try again",
			});
		}
	});

app.get("/logout", function (req, res) {
	req.session.destroy(function (err) {
		req.logout();
		res.redirect("/");
	});
});

app.get("/secrets", function (req, res) {
	if (req.isAuthenticated()) {
		User.find({ secret: { $ne: null } }, function (err, foundUser) {
			if (err) {
				console.log(err);
			} else {
				if (foundUser) {
					res.render("secrets", { userWithSecrets: foundUser });
				}
			}
		});
	} else {
		console.log("test");
		res.redirect("/login");
	}
});

app.get("/mysecrets", function (req, res) {
	if (req.isAuthenticated()) {
		User.findById(req.user.id, function (err, foundUser) {
			if (err) {
				console.log(err);
			} else {
				if (foundUser) {
					res.render("mysecrets", { userWithSecrets: foundUser.secret });
				}
			}
		});
	} else {
		res.redirect("/login");
	}
});

app
	.route("/submit")
	.get(function (req, res) {
		if (req.isAuthenticated()) {
			res.render("submit");
		} else {
			res.redirect("/login");
		}
	})
	.post(function (req, res) {
		const submitSecret = req.body.secret;

		User.findById(req.user.id, function (err, foundUser) {
			if (err) {
				console.log(err);
			} else {
				if (foundUser) {
					foundUser.secret.push(submitSecret);
					foundUser.save(function () {
						res.redirect("/secrets");
					});
				}
			}
		});
	});

app.post("/delete", function (req, res) {
	deleteData = req.body.deleteData;
	console.log(deleteData);
	console.log(req.user.secret);
	console.log(req.user.id);

	User.findOneAndUpdate(
		{ _id: req.user.id },
		{ $pull: { secret: deleteData } },
		(err, doc) => {
			if (err) {
				console.log(err);
			}
		}
	);

	res.redirect("/mysecrets");
});

app.listen(process.env.PORT || 3000, function () {
	console.log("Server is running on server 3000");
});
