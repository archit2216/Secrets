require("dotenv").config();
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const bcrypt=require("bcrypt");
const mongoose=require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy=require("passport-google-oauth20").Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate=require("mongoose-findorcreate");
//password of bcrypt@this.com is 123456 but in db you will see a hash which will take years to crack
const saltRounds=10;
// const encrypt=require("mongoose-encryption"); LEVEL-2 security password:qwerty
// const md5=require("md5"); //LEVEL 3 SECURITY password:123456
const app=express();

//console.log(process.env.API_KEY);

app.use(session({
    secret:"Hi there it's me",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://architsharma:archit@c32@cluster0.pmjk5.mongodb.net/userDB",{useNewUrlParser:true});
mongoose.set('useCreateIndex', true);
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended:true}));


const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
//encrypt password so that user can't read it through DB LEVEL-2 security
// userSchema.plugin(encrypt,{secret:process.env.SECRET,encryptedFields:["password"]});

const User=mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done){done(null, user.id);});
passport.deserializeUser(function(id, done){
    User.findById(id,function(err,user){
        done(null,user);
    });
});
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://radiant-shore-67620.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "https://radiant-shore-67620.herokuapp.com/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate({facebookId:profile.id}, function(err, user) {
      if (err) { return done(err); }
      done(null, user);
    });
  }
));

app.get("/",function(req,res){
    res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
  );

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook', {authType:'reauthenticate'}));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  app.get("/submit",function(req,res){
      if(req.isAuthenticated()==true){
          res.render("submit");
      }else{
          res.redirect("/login");
      }
  });

  app.post("/submit",function(req,res){
      const Thesecret=req.body.secret;
      User.findById(req.user.id,function(err,founduser){
          if(!err){
              founduser.secret=Thesecret;
              founduser.save(function(){
                  res.redirect("/secrets");
              });
          }else{
              console.log(err);
          }
      });
  });
app.get("/login",function(req,res){
    res.render("login");
});

app.get("/register",function(req,res){
    res.render("register");
});

app.get("/secrets",function(req,res){
    User.find({"secret":{$ne:null}},function(err,foundusers){
        if(!err){
            if(foundusers){
                res.render("secrets",{usersWithSecrets:foundusers});
            }
        }
    });
});
app.post("/register",function(req,res){

    User.register({username:req.body.username},req.body.password,function(err,user){
        if(err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
            });
        }
    });
});
    // bcrypt.hash(req.body.password,saltRounds,function(err,hash){
    //     if(!err){
    //         const newUser=new User({
    //             email:req.body.username,
    //             password:hash
    //         });
    //         newUser.save(function(err){
    //             if(!err){
    //                 res.render("secrets");
    //             }else{
    //                 res.send(err);
    //             }
    //         });     
    //     } 
    // }); bcrypt
    // const newUser=new User({
    //     email:req.body.username,
    //     password:md5(req.body.password)
    // });
    // newUser.save(function(err){
    //     if(!err){
    //         res.render("secrets");
    //     }else{
    //         res.send(err);
    //     }
    // }); normal hashing
// });

app.post("/login",function(req,res){
    const user=new User({
        email:req.body.username,
        password:req.body.password
    });

    req.login(user,function(err){
        if(err){
            console.log(err);
        }else{
           passport.authenticate("local")(req,res,function(){
               res.redirect("/secrets");
           });
        }
    });
    // const userName=req.body.username;
    // // const pass=md5(req.body.password);
    // const pass=req.body.password;

    // User.findOne({email:userName},function(err,foundUser){
    //     if(!err){
    //         if(foundUser){
    //             bcrypt.compare(pass,foundUser.password,function(err,result){
    //                 if(!err){
    //                     res.render("secrets");
    //                 }
    //             });
    //         }
    //     }else{
    //         console.log(err);
    //     }
    // })
});

app.get("/logout",function(req,res){
    req.logout();
    res.redirect("/");
});

const port=process.env.PORT || 3000;
app.listen(port,function(){
    console.log("Server has started successfully");
})