const passport = require("passport");
const bcrypt = require("bcrypt");

module.exports = function (app, myDataBase) {
  app.route("/").get((req, res) => {
    // Change the response to render the Pug template
    res.render(process.cwd() + "./views/pug/index", {
      title: "Connected to Database",
      message: "Please login",
      showLogin: true,
      showRegistration: true,
      showSocialAuth: true,
    });
  });
  app.route("/auth/github").get(passport.authenticate("github"));
  app
    .route("/auth/github/callback")
    .get(
      passport.authenticate("github", { failureRedirect: "/" }),
      (req, res) => {
        res.redirect("/profile");
      }
    );
  app.route("/login").post(
    passport.authenticate("local", {
      failureRedirect: "/",
    }),
    (req, res) => {
      res.redirect("/profile", { username: req.user.username });
    }
  );
  app.route("/profile").get(ensureAuthenticated, (req, res) => {
    res.render("profile");
  });
  app.route("/logout").get((req, res) => {
    req.logout();
    res.redirect("/");
  });
  app.route("/register").post(
    (req, res, next) => {
      // before add new user search in a database if exists
      myDataBase.findOne({ username: req.body.username }, (err, user) => {
        if (err) next(err);
        if (user) res.redirect("/");

        const hashedPassword = bcrypt.hashSync(req.body.password, 12);

        myDataBase.insertOne(
          {
            username: req.body.username,
            password: hashedPassword,
          },
          (err, doc) => {
            if (err) res.redirect("/");
            else next(null, doc.ops[0]);
          }
        );
      });
    },
    passport.authenticate("local", { failureRedirect: "/" }),
    (req, res, next) => {
      res.redirect("/profile");
    }
  );
  app.use((req, res, next) => {
    res.status(404).type("text").send("Not Found");
  });
};

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    console.log("authenticated! ... ");
    return next();
  }
  console.log("user is not authenticated!");
  res.redirect("/");
}