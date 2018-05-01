// module imports
const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3');
const Sequelize = require('sequelize');
const crypto = require('crypto');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const app = express();
const router = express.Router();
const handlebars = require("express-handlebars").create({ defaultLayout: 'main' });
app.engine('handlebars', handlebars.engine);
app.set('view engine', 'handlebars');

// body parser config
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({
    extended: true
}));

// connect to db
const sequelize = new Sequelize('mydb', 'YOUR_NAME', null, {
    host: 'localhost',
    dialect: 'sqlite',
    storage: './Chinook_Sqlite_AutoIncrementPKs.sqlite'
});

// define schema
const User = sequelize.define('User', {
    id: {
        type: Sequelize.INTEGER,
        autoIncrement: true,
        primaryKey: true
    },
    firstName: Sequelize.STRING,
    lastName: Sequelize.STRING,
    username: Sequelize.STRING,
    passwordHash: Sequelize.STRING,
    salt: Sequelize.STRING
},
{
    freezeTableName: true,
    timestamps: false
})

User.sync({force: true});

// auth config
app.use(passport.initialize());

passport.serializeUser(function(user, done){
    done(null, user);
});
  
passport.deserializeUser(function(obj, done){
    done(null, obj);
});

passport.use(new LocalStrategy(function(username, password, done){
    User.find({username: username}).then(user => {  
        let salt = crypto.randomBytes(16).toString('hex');
        let passwordHash = crypto.pbkdf2Sync(password, user.salt, 1000, 64, 'sha1').toString('hex');

        if(!user){
            return done(null, false, {message: "Invalid user"});
        } else if(passwordHash !== user.passwordHash) {
            return done(null, false, {message: 'Incorrect password'});
        } else {
            return done(null, user);
        }
    })
}));

// API
app.get('/', (req, res) => {
	res.render('register')
})

app.get('/home', (req, res) => {
    if(!req.user) {
        console.log('not authenticated')
        res.redirect('/login')
    } else {
        console.log('authenticated')      
	    res.render('home')        
    }
})

app.get('/login', (req, res) => {
	res.render('login')
})

app.post('/signup', (req, res) => {
    let salt = crypto.randomBytes(16).toString('hex');
    let passwordHash = crypto.pbkdf2Sync(req.body.password, salt, 1000, 64, 'sha1').toString('hex');
    User.create({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        username: req.body.username,
        passwordHash: passwordHash,
        salt: salt
    })
    res.render('home')
})

app.post('/login', passport.authenticate('local'), (req, res) => {
    res.render('home')
})

// run server on port 3000
app.listen(3000, () => {
    console.log('server running')
})
