require('dotenv').config();
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
const alert = require("alert");

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
    secret: "Thisisthesecret",
    resave: false,
    saveUninitialized: false
   }));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userSecretDB', {useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true});


const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: [String]
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
    });
  }
));


passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ['id', 'emails', 'name'] 
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({username:profile.emails[0].value, facebookId: profile.id }, function (err, user) {
        console.log(profile);
      return cb(err, user);
    });
  }
));

 
app.get("/", function(req,res){
 
    res.render("home");
    
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ['profile'] }));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect("/secrets");
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ["email"]}),
      function(req, res){
  });

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect("/secrets");
  });

app.route("/login")
    .get(function(req,res){
     res.render("login");

    })
    .post(function(req,res){

        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        req.login(user, function(err){
            if(err){
                console.log(err);
            }
            else{
                passport.authenticate("local")(req, res, function(){
                    res.redirect("/secrets");
                });
            }
        })
        
    });

app.route("/register")
    .get(function(req,res){
        res.render("register");
    
    })
    .post(function(req,res){
        
        if(req.body.password === req.body.chackPassword){
            User.register({username: req.body.username}, req.body.password, function(err,user){
                if(err){
                    console.log(err);
                    res.redirect("/register");
                } else {
                    passport.authenticate("local")(req, res, function(){
                        res.redirect("/secrets");
                    });
                }
            });
        } else {
            alert("ERROR");
            res.redirect("/register");
        }
       
               
    });


app.get("/logout", function(req,res){
    req.session.destroy(function(err){
        req.logout();
        res.redirect("/");
    });
    
});
    
app.get("/secrets", function(req,res){
    
    if(req.isAuthenticated()){
        User.find({"secret": {$ne: null}}, function(err, foundUser){
            if(err){
                console.log(err);
            } else {
                if (foundUser) {
                    res.render("secrets", {userWithSecrets:foundUser});
                }
            }
        })
        
    } else {
        res.redirect("/login");
    
    }
   
});

app.route("/submit")
    .get(function(req,res){
        
        if(req.isAuthenticated()){
            res.render("submit");
          } else {
            res.redirect("/login");
          }
        
    })
    .post(function(req,res){

        const submitSecret = req.body.secret

       User.findById(req.user.id, function(err,foundUser){
           if(err){
               console.log(err);
           } else {
               if(foundUser){
                   foundUser.secret.push(submitSecret);
                   foundUser.save(function(){
                       res.redirect("/secrets");
                   });
               }
           }
       });
    });

app.listen(3000, function(){
    console.log("Server is running on server 3000");
})


// colour template used https://colorhunt.co/palette/253219