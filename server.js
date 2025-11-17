const fs = require('fs');
const https = require('https');
const express = require('express');
const { Server } = require('socket.io');
const { MongoClient } = require('mongodb'); // require mongodb client to connect to the database

//************************************************************************************************************************/

// Athena's part
// start of MongoDB connection setup  
// reference: https://www.mongodb.com/blog/post/quick-start-nodejs-mongodb-how-to-get-connected-to-your-database
const uri = 'mongodb+srv://team_access:qn5ulVpH2JFUCXvh@cluster1.skejaaj.mongodb.net/?appName=Cluster1' //connection string to the database
const client = new MongoClient(uri)
let db                  // database object
let usersCollection // collection to store user names and their public keys
let messagesCollection  // collection to store user messages

async function connectDB() {
  try {
    await client.connect()             // wait for connection to mongoDB server
    db = client.db('Secure_Chat_App')       // access Secure_Chat_App database
    usersCollection = db.collection('users') // stores user name and their public keys
    messagesCollection = db.collection('messages') // store user messages
    console.log('[MongoDB] Connected to database.')
  } catch (err) {
    console.error('[MongoDB] Connection failed:', err)
  }
}

//call the function to connect to the database at startup at server initiation
// end of MongoDB connection setup

//************************************************************************************************************************/

// Zeinab's part
const bodyParser = require('body-parser')
const handlebars = require('express-handlebars')
const crypto = require('crypto')
const app = express();
app.use(bodyParser.urlencoded())
app.set('views', __dirname + '/views')
app.set('view engine', 'handlebars')
app.engine('handlebars', handlebars.engine())

// Render registration page
app.get('/register', async (req, res) => {
  res.render('registration', { layout: undefined })
});


// Handle what happens after user registers (includes generation of key pair) THE POST REQUEST :]
app.post('/register', async (req, res) => {
  let username = req.body.username
  let password = req.body.password
  let confirmPassword = req.body.confirmpassword
  let publicKey = req.body.publicKey //ADDED FOR PHASE 3, Receiving RSA PUBLIC KEY from client

  // phase 3 logs, just to see if public key is registered!
  console.log('registration for:', username)
  console.log('public Key:', publicKey ? 'RECEIVED' : 'MISSING') // recieved or missing
  if (publicKey) console.log('Key length:', publicKey.length)

  if (password !== confirmPassword) {
    return res.redirect('/register?error=passwords+do+not+match')
  }

  // I am checking here if the username exists or not if yes we do not allow creation of account
  let existing = await usersCollection.findOne({ username: username })
  if (existing) {
    return res.redirect('/register?error=username+is+taken')
  }

  // Here I am checking the length of the password
  if (password.length < 8) {
    return res.redirect('/register?error=password+must+be+8+or+more+characters')
  }

  let salt = crypto.randomUUID()
  let hash = crypto.createHash('sha256')
  let hashedPassword = hash.update(password + salt).digest('hex')

  let newUser = {
    username: username,
    password: hashedPassword,
    salt: salt,
    publicKey: publicKey, //ADDED FOR PHASE 3, Storing RSA PUBLIC KEY
    online: false,
  }

  // side note: every user will have one rsa pair key upon registering. this does not change anymore. - athena

  await usersCollection.insertOne(newUser)
  res.redirect('/login')
});

// Render the login page
app.get('/login', async (req, res) => {
  res.render('login', { layout: undefined })
});

// I put a simple route that takes you to login if you are in landing page
app.get('/', async (req, res) => {
  res.redirect('/login')
});

// Handle what happens after user logs in (includes authentication)
app.post('/login', async (req, res) => {
  let username = req.body.username
  let password = req.body.password
  console.log('We are trying to log in as:', username)
  let user = await usersCollection.findOne({ username: username })
  if (!user) {
    console.log('Login failed: user not found')
    return res.redirect('/login?error=user+not+found')
  }
  let salt = user.salt
  let hash = crypto.createHash('sha256')
  let updatedHash = hash.update(password + salt)
  let hashedPassword = updatedHash.digest('hex')
  if (hashedPassword !== user.password) {
    console.log('Login failed: wrong password')
    res.redirect('/login')
  }
  await usersCollection.updateOne({ username: username }, { $set: { "online": true } })
  res.redirect(`/account/${username}`)
});

app.get('/account/:name', async (req, res) => {
  const name = req.params.name;
  const users = await usersCollection.find({}).toArray();
  res.render('chat', { layout: false, name, users });
});

app.get('/logout/:name', async (req, res) => {
  let name = req.params.name
  await usersCollection.updateOne({ username: name }, { $set: { "online": false } })
  res.redirect('/login')
});

//************************************************************************************************************************/
// Amani's part
/* -----------------------------------------------------------------------------
// Start HTTPS server and Socket.IO
// -------------------------------------------------------------------------- */

// Serve our static client app
app.use(express.static('public'));

// Load SSL certificates
const options = {
  key: fs.readFileSync('certs/key.pem'),
  cert: fs.readFileSync('certs/cert.pem')
};

// Start HTTPS server
const server = https.createServer(options, app)

// Initialize Socket.IO
const io = new Server(server)

// Listen for Socket.IO connections
io.on('connection', (socket) => {
  console.log('A user connected');

  // PHASE 3 UPDATE: new socket event to handle public key requests from client side
  socket.on('request-public-key', async (data, callback) => {
    // this one is connected to client.js socket.emit('request-public-key', {username:recipient}, (res) => {
    // we used callback here to send the public key back to client when we find it in the database
    // basically 
    const username = data.username;
    console.log(`public key requested for: ${username}`)

    try {
      // here we query for the user in the database
      const user = await usersCollection.findOne({ username: username })

      // here find public key
      if (!user || !user.publicKey) {
        console.log(`public key not found for: ${username}`)
        return callback({
          ok: false,
          error: 'User or public key not found'
        });
      }

      // send public key back via callback
      console.log(`public key sent for: ${username}`)
      callback({
        ok: true,
        publicKey: user.publicKey
      });

    } catch (err) {
      console.error(`database error:`, err);
      callback({
        ok: false,
        error: 'Database error'
      });
    }
  });

  // Register socket with username
  socket.on('register', async (data) => {  // the data here contains the username from client server socket.emit(regiter)
    socket.username = data.username;
    console.log(`user registered: ${socket.username}`)

    await usersCollection.updateOne(
      { username: socket.username },
      { $set: { online: true } })

    // Send updated user list to all clients
    const users = await usersCollection.find({}).toArray()
    io.emit('user-list', users)
  });


  //  PHASE 3 UPDATE: new socket event to handle session key exchange between clients, connected to client.js socket.emit('session-key-exchange' etc...
  // basically, this makes server receive the encrypted session key from sender, then deliver it to recipient without decrypting it
  socket.on('session-key-exchange', async (data) => {
    console.log(`session key: ${data.sender} → ${data.recipient}`)

    // here we validate the data
    // data includes sender, recipient, encryptedSessionKey(the AES session key encrypted with recipient's public key)
    if (!data.sender || !data.recipient || !data.encryptedSessionKey) {
      console.error('invalid session key data')
      return;
    }

    // Find recipient's socket connection
    const sockets = Array.from(io.sockets.sockets.values())
    const targetRecipient = sockets.find(s => s.username === data.recipient)

    if (targetRecipient) {
      // this is for callback for confirmation
      targetRecipient.emit('session-key-exchange', data, (confirmation) => {
        // Find sender's socket
        const senderSocket = sockets.find(s => s.username === data.sender)
        if (senderSocket && confirmation?.ok) {
          // Tell sender that recipient got the key
          senderSocket.emit('session-key-confirmed', {
            recipient: data.recipient
          });
        }
      });

      // deliver encrypted key if recipient is online
      if (targetRecipient) {
        targetRecipient.emit('session-key-exchange', data)
        console.log(`key delivered to ${data.recipient}`)
      } else {
        console.log(`${data.recipient} is offline`)
      }

      // phase 3, notify sender if recipient offline
      const senderSocket = sockets.find(s => s.username === data.sender)
      if (senderSocket) {
        senderSocket.emit('session-key-failed', {
          recipient: data.recipient,
          reason: 'User is offline'
        });
      }
    }
  });

  // handle encrypted messages
  // phase 3 update: msg is now an object with multiple items sender info, recipeint, initial vector, and ciphertext
  socket.on('encrypted-message', async (msg) => {
    console.log(`message: ${msg.sender} → ${msg.recipient}`) //we just want to confirm that server received the message

    // to validate the data sent!
    if (!msg.sender || !msg.recipient || !msg.ivB64 || !msg.ctB64) {
      console.error('invalid message structure')
      return;
    }

    // Save to MongoDB
    await messagesCollection.insertOne(msg)

    // send to recipient if online
    const sockets = Array.from(io.sockets.sockets.values())
    const target = sockets.find(s => s.username === msg.recipient)
    if (target) target.emit('encrypted-message', msg)
  });

  // Handle disconnect
  socket.on('disconnect', async () => {
    if (socket.username) {
      await usersCollection.updateOne(
        { username: socket.username },
        { $set: { online: false } }
      );
      const users = await usersCollection.find({}).toArray();
      io.emit('user-list', users);
    }
  });
});

/* -----------------------------------------------------------------------------
// Start HTTPS server with MongoDB connection
// -------------------------------------------------------------------------- */

(async () => {
  await connectDB(); // wait for MongoDB connection
  const PORT = process.env.PORT || 3001; // change to 3000 for final deployment
  server.listen(PORT, () => {
    console.log(`HTTPS server running at https://localhost:${PORT}`);
    console.log(`Accept the self-signed certificate warning in your browser.`);
  });
})(); 
