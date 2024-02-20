import express from "express";
import bodyParser from "body-parser";
import pg from 'pg';
import bcrypt from 'bcrypt';
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

const db = new pg.Client({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT
})
db.connect();

app.use(session({
  secret: process.env.SESSION_SECRET,
  cookie: {
    maxAge: 1000 * 60 * 60 * 24
  },
  resave: false,
  saveUninitialized: true
}));

app.use(passport.initialize()); 
app.use(passport.session());

app.use(express.static('public'))
app.use(bodyParser.urlencoded({extended:true}))

// GET USER FROM DATABASE

async function getUserIfExists(pEmail) {
  const result = await db.query('SELECT * FROM users WHERE email = $1', [pEmail])
  const user = result.rows[0]
  return user
}

// ADD TO DATABASE A REGISTER

async function addRegisterToDatabase(pEmail, pPassword) {
  const newUser = await db.query('INSERT INTO users (email, password) VALUES ($1 ,$2) RETURNING *', [pEmail, pPassword])
  return newUser
}

app.get('/', (req, res) => {
  res.render('home.ejs')
});

app.get('/login', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('secrets.ejs')
  } else {
    res.render('login.ejs')
  }
});

app.get('/register', (req, res) => {
  res.render('register.ejs')
});

app.get('/secrets', (req, res) => {
  console.log(req.user)
  if (req.isAuthenticated()) {
    res.render('secrets.ejs')
  } else {
    res.redirect('/login')
  }
});

app.post('/register', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (await getUserIfExists(username)) {
    console.log('The email already exists')
    res.redirect('/register')
  } else {
    bcrypt.hash(password, saltRounds, async function(err, hash) {
      if (err) {
        console.log(err)
      } else {
        const result = await addRegisterToDatabase(username, hash)
        const user = result.rows[0];
        req.login(user, (err) => {
          if (err) {console.log(err)}
          res.redirect('/secrets')
        })
      }
    })
  }
});

app.post('/login', passport.authenticate('local', {
  successRedirect: '/secrets',
  failureRedirect: '/login'
}));

passport.use(new Strategy(async function (username, password, cb){
  const user = await getUserIfExists(username)
  
  if (user) {
    bcrypt.compare(password, user.password, function(err, result) {
      if(err) {
        cb(err)
      } else {
        if (result) {
          cb(null, user)
        } else {
          cb(null, false)
        }
      }
    });
  } else {
    cb(null, false)
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user)
});

passport.deserializeUser((user, cb) => {
  cb(null, user)
});

app.listen(port, () => {
  console.log('The server is running at port: ' + port)
});
