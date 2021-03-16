require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

mongoose.connect('mongodb://localhost:27017/userSecretDB', {useNewUrlParser: true, useUnifiedTopology: true});

const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));


const userSchema = new mongoose.Schema({
    email: String,
    password:String
});


userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model("User", userSchema);

 
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
            if(foundUser){
                if(checkPassword===foundUser.password){
                res.render("secrets");
                } else {
                    console.log(err);
                }
                
            } else {
                console.log(err);
            }
        })
    });

app.route("/register")
    .get(function(req,res){
        res.render("register");
    
    })
    .post(function(req,res){
        const newUser = new User({
            email: req.body.username,
            password: req.body.password
        });
        
        newUser.save(function(err){
            if(!err){
                res.render("Secrets");
                res.redirect("/login");
            } else {
                console.log("err");
                res.redirect("/login");
            }
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