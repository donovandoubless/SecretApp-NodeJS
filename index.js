require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

mongoose.connect('mongodb://localhost:27017/userSecretDB', {useNewUrlParser: true, useUnifiedTopology: true});

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));


const userSchema = new mongoose.Schema({
    email: String,
    password:String
});

const User = new mongoose.model("User", userSchema);

const saltRounds = 10;

 
app.get("/", function(req,res){
 
    res.render("home");
    
});

app.route("/login")
    .get(function(req,res){
     res.render("login");

    }).post(function(req,res){
        const checkEmail = req.body.username;
        const checkPassword = req.body.password;

        User.findOne({email:checkEmail}, function(err,foundUser){
            if(err){
                console.log(err);
            } else if (foundUser){
                bcrypt.compare(checkPassword, foundUser.password, function(err, result) {
                    if (result=== true){
                        res.render("secrets"); 
                    } else {
                        console.log(err);
                    }
                    
                });
            }
        });
    });

app.route("/register")
    .get(function(req,res){
        res.render("register");
    
    })
    .post(function(req,res){


        bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
            const newUser = new User({
                email: req.body.username,
                password: hash
            });
            
            newUser.save(function(err){
                if(!err){
                    res.render("secrets"); 
                } else {
                    console.log("err");
                    res.redirect("/login");
                }
            });
        });

        
    });

  
    
app.get("/secrets", function(req,res){
 
    res.render("secrets");
    
});

app.get("/submit", function(req,res){
 
    res.render("submit");
    
});

app.listen(3000, function(){
    console.log("Server is running on server 3000");
})


// colour template used https://colorhunt.co/palette/253219