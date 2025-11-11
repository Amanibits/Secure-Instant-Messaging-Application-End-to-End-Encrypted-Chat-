// server.js — Secure IM (Phase 1 + Phase 2)
// -----------------------------------------------------------------------------
// WHAT THIS FILE DOES
//   • Serves static files (index.html, styles.css, client.js) over HTTPS
//   • Hosts a Socket.IO server for realtime messaging
//   • Stores only ciphertext + routing metadata (sender, recipient, ts)
//   • Routes messages to the intended recipient (not broadcast)
//   • Tracks presence (who’s online) and a known users list (incl. offline)
//   • Emits delivery + read receipts
//
// SECURITY GUARANTEES (Phase 1/2 scope):
//   • Server never sees plaintext messages nor keys
//   • Server stores iv + ciphertext only (and non-secret metadata)
//   • Symmetric AES-GCM key is pre-shared out of band (Phase 1 requirement)
//
// FILE STRUCTURE
//   /public/index.html  — UI + inputs for name, key, message
//   /public/styles.css  — look and feel
//   /public/client.js   — WebCrypto (AES-GCM) + UI + Socket.IO client
//
// RUN
//   node server.js   (make sure certs/key.pem and certs/cert.pem exist)
// -----------------------------------------------------------------------------

const fs = require('fs');
const https = require('https');
const express = require('express');
const { Server } = require('socket.io');

const app = express();

// Serve our static client app
app.use(express.static('public'));

// Local HTTPS for WebCrypto (subtle crypto requires HTTPS or localhost)
const server = https.createServer({
  key: fs.readFileSync('certs/key.pem'),
  cert: fs.readFileSync('certs/cert.pem'),
}, app);

// Socket.IO over the same HTTPS server
const io = new Server(server, { cors: { origin: true, credentials: true } });

/* -----------------------------------------------------------------------------
   In-memory state (simple, Phase 1/2 acceptable)
   -------------------------------------------------------------------------- */

// online: username -> Set<socketId>  (multiple tabs allowed)  
const online = new Map();

// knownUsers: Set<username> (includes offline users so @mentions can suggest them)
const knownUsers = new Set();

// messages array stores ciphertext only + tiny routing metadata
//   { id, sender, recipient, ivB64, ctB64, ts, delivered, read }
const messages = [];


/* -----------------------------------------------------------------------------
   Small helpers (presence + lists)
   -------------------------------------------------------------------------- */

function attachUser(username, socketId) {
  const set = online.get(username) || new Set();
  set.add(socketId);
  online.set(username, set);
}
function detachSocket(socketId) {
  for (const [user, set] of online) {
    if (set.delete(socketId)) {
      if (!set.size) online.delete(user);
      return user;
    }
  }
  return null;
}

// Build lists for presence UI (online first; “all” also includes offline)
function userLists() {
  const onlineUsers = [...online.keys()].sort();
  const all = new Set([...knownUsers, ...onlineUsers]);
  const allUsers = [...all].sort();
  return { online: onlineUsers, all: allUsers };
}
function broadcastPresence() {
  const lists = userLists();
  io.emit('presence', lists);
}

/* -----------------------------------------------------------------------------
   Socket.IO lifecycle
   -------------------------------------------------------------------------- */

io.on('connection', (socket) => {
  console.log(`[+] Connected ${socket.id}`);

  // 1) Registration: client claims a username (no passwords in Phase 2)
  socket.on('register', (username, ack) => {
    const name = (typeof username === 'string' ? username.trim() : '');
    if (!name || name.length > 32) {
      ack?.({ ok: false, error: 'Invalid username' });
      return;
    }

    knownUsers.add(name);
    attachUser(name, socket.id);
    socket.data.username = name;

    // Send personal history (messages where I’m sender or recipient)
    const mine = messages.filter(m => m.sender === name || m.recipient === name);
    socket.emit('history', mine);

    // If a user just came online, mark pending messages as delivered now
    const newlyDelivered = [];
    for (const m of messages) {
      if (m.recipient === name && !m.delivered) {
        m.delivered = true;
        newlyDelivered.push(m);
      }
    }

    // Tell senders that their messages reached the recipient device(s)
    for (const m of newlyDelivered) {
      const senderSet = online.get(m.sender);
      if (senderSet) {
        for (const sid of senderSet) {
          io.to(sid).emit('delivery-receipt', { id: m.id });
        }
      }
    }

    broadcastPresence();
    ack?.({ ok: true, ...userLists() });
    console.log(`[=] Registered "${name}" on ${socket.id}`);
  });

  // Encrypted message from client (ciphertext already produced in the browser)
  //    packet: { sender, recipient, ivB64, ctB64 }
  socket.on('encrypted-message', (packet, ack) => {
    const { sender, recipient, ivB64, ctB64 } = packet || {};

    // server-side sanity check of shape
    if (typeof ivB64 !== 'string' || typeof ctB64 !== 'string') {
      ack?.({ ok: false, error: 'Bad packet shape' });
      return;
    }

    const safeSender = (typeof sender === 'string' && sender.trim() && sender.length <= 32)
      ? sender.trim() : 'Anonymous';
    const safeRecipient = (typeof recipient === 'string' && recipient.trim() && recipient.length <= 32)
      ? recipient.trim() : null;

    if (!safeRecipient) {
      ack?.({ ok: false, error: 'Recipient required' });
      return;
    }

    // Track recipient in known list so it shows up in @ menu even if offline
    knownUsers.add(safeSender);
    knownUsers.add(safeRecipient);

    // delivery flag at send time (true if recipient is online now)
    const isRecipientOnline = !!(online.get(safeRecipient) && online.get(safeRecipient).size);

    // store ciphertext + routing metadata; NO plaintext, NO keys
    const msg = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2),
      sender: safeSender,
      recipient: safeRecipient,
      ivB64, ctB64,
      ts: new Date().toISOString(),
      delivered: isRecipientOnline, // true if user is currently online
      read: false                    // flips to true when recipient marks read
    };
    messages.push(msg);

    // Route to recipient’s sockets only (no broadcast)
    const targetSet = online.get(safeRecipient);
    if (targetSet && targetSet.size) {
      for (const sid of targetSet) io.to(sid).emit('encrypted-message', msg);
    } else {
      // Recipient offline: stored for later, delivered on next register()
      console.log(`[i] Recipient "${safeRecipient}" offline; stored message ${msg.id}`);
    }

    // ack to sender includes whether it was delivered immediately
    ack?.({ ok: true, id: msg.id, delivered: isRecipientOnline });
  });

  // Recipient marks messages as READ (server flips read=true and notifies sender)
  socket.on('mark-read', (ids) => {
    const me = socket.data.username;
    if (!me || !Array.isArray(ids)) return;
    for (const id of ids) {
      const msg = messages.find(m => m.id === id);
      if (msg && msg.recipient === me && !msg.read) {
        msg.read = true;
        const senderSet = online.get(msg.sender);
        if (senderSet) {
          for (const sid of senderSet) {
            io.to(sid).emit('read-receipt', { id: msg.id });
          }
        }
      }
    }
  });

  // Client requests user lists (online + all)
  socket.on('list-users', (ack) => {
    ack?.({ ok: true, ...userLists() });
  });

  // Handle disconnects, clean up presence state
  socket.on('disconnect', () => {
    const user = detachSocket(socket.id);
    if (user) {
      console.log(`[-] ${user} (${socket.id}) disconnected`);
      broadcastPresence();
    }
  });
});


/* -----------------------------------------------------------------------------
   Start HTTPS server
   -------------------------------------------------------------------------- */

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`   HTTPS server on https://localhost:${PORT}`);
  console.log(`   Self-signed cert: accept the warning in your browser once.`);
});
