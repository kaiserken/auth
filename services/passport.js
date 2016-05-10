const passport  = require('passport');
const User  = require('../models/user');
const config  = require('../config/index');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;

// set up options
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

//create jwt Strategy

const jwtLogin  = new JwtStrategy(jwtOptions, function(payload, done){
  // see if user id in payload exists in Db - if yes call done with user
  User.findById(payload.sub, function(err, user){
    if (err){ return done(err, false);}

    if (user){
      done(null, user);
    } else {
      done(null, false);
    }
  });

});

// tell passport to use this strategy
passport.use(jwtLogin);
