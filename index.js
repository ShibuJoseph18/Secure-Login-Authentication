import express from "express";
import bodyParser from "body-parser";//retrive data
import pg from "pg";
// import { render } from "ejs";
import bcrypt from "bcrypt";
import session from "express-session";//repeat
import passport, { Passport } from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";


const app = express();//create xp app
const port = 3000;
const saltRounds = 15;
env.config();

const db = new pg.Client({
  user: process.env.USER,
  host: process.env.HOST,
  database: process.env.AUTH,
  password: process.env.PASSWORD,
  port: process.env.PORT,
});
db.connect();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true ,
  cookie: {
    maxAge: 1000 * 60 * 60,
  }
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(bodyParser.urlencoded({ extended: true }));//midleware to parse data 
app.use(express.static("public"));


function showDesiredPage(res, pagename, errortype, errormessage) {
  // This function helps to render the desired page with specified input placeholders
  if (!errormessage) {
    res.render(pagename);
    // return
  }
  else if (errortype == "emailError") {
    res.render(pagename, {
      emailError:true,
      error: errormessage,
    });
  } else {
    res.render(pagename, {
      passwordError: true,
      error: errormessage,
    });
  }
}

app.get("/", (req, res) => {
  showDesiredPage(res, "home.ejs");
});

app.get("/login", (req, res) => {
  showDesiredPage(res, "login.ejs");
});

app.get("/register", (req, res) => {
  showDesiredPage(res, "register.ejs");
});

app.get("/secrets", (req, res) => {
  console.log(req.user);
  if (req.isAuthenticated()) {
    showDesiredPage(res, "secrets.ejs");
  } else {
    showDesiredPage(res, "login.ejs");
  }
})

app.post("/register", async (req, res) => {

  const userCredentials = req.body;
  console.log(userCredentials);
  const username = userCredentials.username;
  const password = userCredentials.password;
  console.log(username);
  if (username) { // Check for presence of user email
    if(password) { // Check for presence of user password
      let checkEmail = await db.query(`SELECT * FROM user_credentials 
      WHERE email_id = $1`, // Check email if already exists
      [username]
      );
      console.log(checkEmail);
      // console.log(checkEmail);
      if (checkEmail.rows.length === 0) { // Ensure each email is registered only once.
        try {
          // Password hashing
          bcrypt.hash(password, saltRounds, async(err, hash) => {
            if (err) {
              console.log("Error hashing password", err);
            } else {
              const result = await db.query(`INSERT INTO user_credentials(email_id, password)
              VALUES($1, $2)`,
              [username, hash]
              );
            }
          });
          res.render("login.ejs");
        } catch (error) {
          console.log(error);
        }
      } else {
        showDesiredPage(res, "register.ejs", "emailError", "Email already exists")
        console.log("email exists");
      }  
    } else {
      showDesiredPage(res, "register.ejs", "passwordError", "Password unfilled")
      console.log("Pass unfilled");
    }
  } else {
    showDesiredPage(res, "register.ejs", "emailError", "Email unfilled")
    console.log("Email unfilled");
  }
});

// app.post("/login", async (req, res) => {
  //google authentication integrate s1
  // nodemon index.js
  // http://localhost:3000/  
//   const userCredentials = req.body;
//   const username = userCredentials.username;
//   const password = userCredentials.password;
//   console.log(username, password);
//   passport.use(new Strategy(async function verify(username, password, cb) {
//     if (username) { // Check for presence of user email
//       if(password) { // Check for presence of user password
//         const checkEmail = await db.query(`SELECT * FROM user_credentials 
//         WHERE email_id = $1`,
//         [username]
//         );
//         console.log("check email",checkEmail.rows[0].password);

//         if (checkEmail.rows.length > 0) { // Check for presence of user email in the database
//           console.log("working");
//           const storedhashPassword = checkEmail.rows[0].password;
//           bcrypt.compare(password, storedhashPassword, (err, result) => {
//             if(err) {
//               console.log("Error comparing password", err);
//               res.render("login.ejs");
//             } else {
//               console.log(result);
//               if (result) { // Ensure the current password and stored hash password is same
//                 console.log("correct", result);
//                 showDesiredPage(res, "secrets.ejs");
//               } else {
//                 showDesiredPage(res, "login.ejs", "passwordError", "Password wrong");
//               }
//             }
//           });
//         } else {
//           console.log("Please register email");
//           showDesiredPage(res, "register.ejs", "emailError", "Please register your email before login");
//         }
//       } else {
//         showDesiredPage(res, "register.ejs", "passwordError", "Password unfilled");
//         console.log("Pass unfiled");
//       }
//     } else {
//       showDesiredPage(res, "login.ejs", "emailError", "Email unfilled");
//       console.log("Email unfilled");
//     }
//   }));
// });

app.post("/login", passport.authenticate("local",{
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));



passport.use(new Strategy(async function verify(username, password, cb) {
  console.log("serive");
  if (username) { // Check for presence of user email
    if(password) { // Check for presence of user password
      const checkEmail = await db.query(`SELECT * FROM user_credentials 
      WHERE email_id = $1`,
      [username]
      );
      // console.log("check email",checkEmail.rows[0].password);
      if (checkEmail.rows.length > 0) { // Check for presence of user email in the database
        console.log("working");
        const storedhashPassword = checkEmail.rows[0].password;
        bcrypt.compare(password, storedhashPassword, (err, result) => {
          if(err) {
            console.log("Error comparing password", err);
            return cb(err);
          } else {
            console.log(result);
            if (result) { // Ensure the current password and stored hash password is same
              console.log("correct", result);
              return cb(null, checkEmail);
              showDesiredPage(res, "secrets.ejs");
            } else {
                return cb(null, false);
                showDesiredPage(res, "login.ejs", "passwordError", "Password wrong");
            }
          }
        });
      } else {
          console.log("Please register email");
          // return cb("Please register email")
          showDesiredPage(res, "register.ejs", "emailError", "Please register your email before login");
      }
    } else {
        showDesiredPage(res, "register.ejs", "passwordError", "Password unfilled");
        console.log("Pass unfiled");
    }
  } else {
      showDesiredPage(res, "login.ejs", "emailError", "Email unfilled");
      console.log("Email unfilled");
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});
  
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
