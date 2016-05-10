const passport  = require('passport');
const User  = require('../models/user');
const config  = require('../config/index');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');
const localOptions = {usernameField: 'email'};

const localLogin = new LocalStrategy(localOptions, function(email, password, done){
  // verify this email and password  - then call done with result
  User.findOne({ email: email }, function(err, user){
    if (err){ return done(err);}
    if (!user){ return done(null, false);}
    // compare passwords here using bcrypt
    user.comparePassword(password, function(err, isMatch){
      if (err) { return done(err); }
      if (!isMatch) { return done(null, false); }
      // this will be assigned to req.user in the done callback
      return done(null, user);
    });
  });
});


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
passport.use(localLogin);
