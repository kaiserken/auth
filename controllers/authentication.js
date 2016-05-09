const jwt  = require('jwt-simple');
const User  = require('../models/user');
const config  = require('../config/index');

function tokenForUser(user){
  const timestamp  = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

exports.signup = function(req, res, next){
  const email  = req.body.email;
  const password  = req.body.password;

  if (!email || !password){
    return res.status(422).send({error: "You must provide an email and password"});
  }
  // see if a user with a given email exists
  User.findOne({email: email}, function(err, existingUser){
    if(err){return next(err);}

    // if  user already exists return an error
    if(existingUser){
      return res.status(422).send({ error: 'Email in use' });
    }
    // save user if it doesn't exists
    const user  = new User({
      email: email,
      password: password
    });
    user.save(function(err){
      if(err){return next(err);}
    // respond to request indicating creation
    // produce a token here
    // user id + seccret string
      res.json({token: tokenForUser(user)});
    });

  });

};
