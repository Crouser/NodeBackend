var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var User = require('./models/user');


const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

var JwtStrategy = require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken'); // used to create, sign, and verify tokens

var config = require('./config.js');

passport.use(new LocalStrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());



exports.getToken = function(user) {
    return jwt.sign(user, config.secretKey,
        {expiresIn: 3600});
};

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.secretKey;

exports.jwtPassport = passport.use(new JwtStrategy(opts,
    (jwt_payload, done) => {
        console.log("JWT payload: ", jwt_payload);
        User.findOne({_id: jwt_payload._id}, (err, user) => {
            if (err) {
                return done(err, false);
            }
            else if (user) {
                return done(null, user);
            }
            else {
                return done(null, false);
            }
        });
    }));

exports.verifyUser = passport.authenticate('jwt', {session: false});


exports.verifyAdmin = (passport.authenticate.verifyUser,(req,res,next) => {
    if(req.user.admin === true){
        next();
    }                                                                                         //errr
    else{
    res.statusCode = 403;
    res.end('You are not authorized to perform this operation!');
    (err)=> next(err);
    }
    res.statusCode = 403;
    res.end('You are not a registered user!');
    (err)=> next(err);

});



exports.verifyAuthor = (passport.authenticate.verifyUser,(req,res,next) => {
    if(req.user._id.equals(comments.author._id)){
        next();
    }
    else{                                                                                 //errr
    res.statusCode = 403;
    res.end('You are not authorized to perform this operation!');
    (err)=> next(err);
    }
    res.statusCode = 403;
    res.end('You are not a registered user!');
    (err)=> next(err);

});

