const passport = require("passport");
const LocalStrategy = require("passport-local");
const bcrypt = require("bcrypt");
const { ObjectID } = require("mongodb");

module.exports = function (app, myDataBase) {
     passport.serializeUser((user, done) => {
       done(null, user._id);
     });
     passport.deserializeUser((id, done) => {
       myDataBase.findOne({ _id: new ObjectID(id) }, (err, doc) =>
         done(null, doc)
       );
     });
     passport.use(
       new LocalStrategy((username, password, done) => {
         myDataBase.findOne({ username }, (err, user) => {
           console.log(`User ${username} attempted to log in.`);
           if (err) {
             console.log("error findOne...");
             return done(err);
           }
           if (!user) return done(null, false);
           // if (password !== user.password) return done(null, false);
           if (!bcrypt.compareSync(password, user.password)) {
             return done(null, false);
           }
           return done(null, user);
         });
       })
     );
};
