const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs')
const session = require('express-session');
const connectSessionKnex = require('connect-session-knex');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

//have to execute it with the session library so that it works
const KnexSessionStore = connectSessionKnex(session)

const sessionConfig = {
  name: 'just a name', //essentially session ID
  //this should not be coded in
  secret: 'just a random secret',
  cookie: {
    maxAge: 1000 * 60 * 60,
    //using https:, use in real world
    secure: false,
    httpOnly: true //browser cant access via js
  },
  resave: false,
  saveUninitilized: false,
  //defaults to locally on the server
  store: new KnexSessionStore({
    knex: db,
    tablename: 'sessions',
    sidfieldname: 'sid',
    createtable: true,
    clearInterval: 1000 * 60 * 60
  })
}


server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig));


server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
    let user = req.body;
    console.log('password arriving from client', user.password)
    user.password = bcrypt.hashSync(user.password, 10); //running through the hash a certain amount of times
    console.log('password heading to db', user.password)
    Users.add(user)
      .then(saved => {
        req.session.user = saved;
        res.status(201).json(saved);
      })
      .catch(error => {
        res.status(500).json(error);
      });
  });
  
  server.post('/api/login', (req, res) => {
    let { username, password } = req.body;
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {

          req.session.user = user;
          res.status(200).json({ message: "Logged In" });
        } else {
          res.status(401).json({ message: 'shall not pass' });
        }
      })
      .catch(error => {
        res.status(500).json(error);
      });
  });
  
  
  //we are going to make this protected
  server.get('/api/users', restricted, (req, res) => {
    Users.find()
      .then(users => {
        res.json(users);
      })
      .catch(err => res.send(err));
  });
  
  function restricted(req, res, next){
    const {username, password } = req.headers;
  
    if (username && password) {
      Users.findBy({ username }) 
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(400).json({message: "invalid credentials"})
        }
      })
      .catch(err => {
        res.status(500).json({message: "unexpected error"})
      })
    } else {
      res.status(400).json({message: "please provide username and passsword"})
    }
  }

  server.get('/logout', (req, res) => {
    if (req.session) {
      req.session.destroy(err => {
        if (err) {
          res.json({
            message: "you can checkout but you cant leave"
          });
        } else {
          res.end();
        }
      })
    }
  })

const port = process.env.PORT || 6000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
