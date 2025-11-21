// Amani's part
// -----------------------------------------------------------------------------
// ROLE OF THIS FILE
//   • Owns the key (WebCrypto AES-GCM) and does all encrypt/decrypt in-browser
//   • Talks to server via Socket.IO with ciphertext only
//   • Renders UI, picks recipient , timestamps, and message status
//
// DATA FLOW (browser):
//   plaintext --AES-GCM--> {iv, ciphertext}  ---> server
//   server stores {sender, recipient, ivB64, ctB64, ts, delivered, read}
//
//  UPDATES:
// - Manual AES generation removed (user pastes Base64 32-byte key), update to automatically generate
// 
// -----------------------------------------------------------------------------

/* -----------------------------------------------------------------------------
   Small UI helper for blinking bubbles into the log
   addMsg(text, cls, ts?, status?, id?)
   -------------------------------------------------------------------------- */

function addMsg(text, cls, ts, status, id) {
  // readded this one to send error messages on the chat ui.
  const log = document.getElementById('messageLog') || document.getElementById('messages')
  if (!log) {
    console.log(`[addMsg] ${text}`)  // At least log it if no UI element
    return;
  }

  const div = document.createElement('div')
  div.className = `msg ${cls}`
  if (id) div.dataset.mid = id

  const bubble = document.createElement('div')
  bubble.className = 'bubble'
  bubble.textContent = text

  const meta = document.createElement('div')
  meta.className = 'meta'
  const time = formatTs(ts)
  meta.innerHTML = `${time ? `<span class="time">${time}</span>` : ''}${status ? ` • <span class="status">${status}</span>` : ''}`

  div.appendChild(bubble)
  if (meta.textContent) div.appendChild(meta)
  log.appendChild(div)
  log.scrollTop = log.scrollHeight
}

// Timestamp helper — keeps UI minimal (HH:MM local time)
function formatTs(iso) {
  if (!iso) return ''
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return ''
  const hh = String(d.getHours()).padStart(2, '0')
  const mm = String(d.getMinutes()).padStart(2, '0')
  return `${hh}:${mm}`
}

/* ----------------------------------------------------------------------------- 
   Username state (Phase 2 “account lite”) 
   -------------------------------------------------------------------------- */
let displayName = null

function setDisplayName(name) {
  const n = (name || '').trim()
  if (!n) throw new Error('Name cannot be empty.')
  if (n.length > 32) throw new Error('Name too long (max 32 chars).')
  displayName = n
  sessionStorage.setItem('displayName', n)
  addMsg(`Name set to: ${n}`, 'sys')

  // Register with server for routing + personal history
  if (socket?.connected) {
    // PHASE 3 update: made username as an object to include public key later
    socket.emit('register', { username: displayName }, (res) => {
      if (!res?.ok) addMsg(`Register failed: ${res?.error || 'unknown'}`, 'sys')
      else updateUserLists(res)
    })
  }
}

function ensureNameLoaded() {
  if (displayName) return displayName
  const cached = sessionStorage.getItem('displayName')
  if (cached) displayName = cached
  return displayName
}

/* ----------------------------------------------------------------------------- 
   Recipient state 
   -------------------------------------------------------------------------- */
let currentRecipient = null

async function setRecipient(name) {
  const n = (name || '').trim()
  if (!n) throw new Error('Recipient cannot be empty.')
  if (n.length > 32) throw new Error('Recipient too long (max 32 chars).')
  currentRecipient = n
  sessionStorage.setItem('recipient', n)
  addMsg(`Recipient set to: ${n}`, 'sys')

  // UPDATE FOR PHASE 3: to initialize session key when recipient is set
  await initializeSessionKey(n);
  // when this happens, key exchange will also be triggered to securely send the session key to the recipient
}

function ensureRecipientLoaded() {
  if (currentRecipient) return currentRecipient
  const cached = sessionStorage.getItem('recipient')
  if (cached) currentRecipient = cached
  return currentRecipient
}

/* ----------------------------------------------------------------------------- 
   Base64 helpers (tolerant of whitespace and URL-safe forms) 
   -------------------------------------------------------------------------- */
function normalizeB64(b64) {
  let s = (b64 || '').trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  return s + '==='.slice((s.length + 3) % 4)
}
function b64ToBytes(b64) {
  const s = normalizeB64(b64)
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}
function bytesToB64(bytes) {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin)
}

const sessionKeys = {} // emptyy object to hold session keys for each user chat. this session key is the automatically generated AES key later you'll see in the code.

// when we say session key, we mean the AES key used for encrypting the message between our users!
// so this is the AES key generator function
async function generateSessionKey() {
  const key = await crypto.subtle.generateKey(
    {
      name: 'AES-GCM',    // Type of encryption
      length: 256         // 256 bits = super strong
    },
    true,                 // Can we export this key? Yes
    ['encrypt', 'decrypt'] // What can we do? Encrypt and decrypt

  );
  return key
}

// Athena's part, phase 3
// Session Key Initialization WHEN chatting with someone
// basically, we call this function when user selects someone to chat with
// this also is temporary! so we renew session keys after some time.
// for simplicity, we are implementing 2 minute renewal time for session keys.
// auto generate after 2 minutes of key creation.

const session_lifetime = 2 * 60 * 1000 // 2 minutes in milliseconds

async function initializeSessionKey(recipient) {

  // here we check if we already have a key for the reciever,, makes sure that we do not generate multiple keys for same user for every message sent
  if (sessionKeys[recipient]) {
    const session = sessionKeys[recipient]
    const keyAge = Date.now() - session.timestamp // just to check how old the key is

    // checker if key still valid
    if (keyAge < session_lifetime) {
      console.log(`using existing key for ${recipient} (${Math.floor(keyAge / 1000)}s old)`)
      return session.aesKey;
    } else {
      // 2 minutes passed already, so we need to renew the key
      console.log(`key expired for ${recipient} (${Math.floor(keyAge / 1000)}s old). now renewing.`)
    }
  }

  // this is where we call generate session key function to create a new AES key, works for both new and renewing old keys
  console.log(`generating new key for ${recipient}`)
  const aesKey = await generateSessionKey()

  // this is to delete the old expired key after renewal
  if (sessionKeys[recipient]) {
    console.log(`old key deleted for ${recipient}`)
    delete sessionKeys[recipient]
  }

  // here we store the new aes key with the timestamp of its creation to reset the timer for next renewal
  sessionKeys[recipient] = {
    aesKey: aesKey,
    timestamp: Date.now() // When this key was created
  };

  // this, we call the other function to securely give the session key to the recipient
  await exchangeSessionKey(recipient, aesKey)
  console.log(`the session key reinitialized and exchanged for ${recipient}`)
  return aesKey;
}

// NEW FUNCTION TO EXCHANGE THE SESSION KEY WITH THE RECIPIENT
// this function encrypts the session key with recipient RSA pubkey and sends it to them via socket.io
async function exchangeSessionKey(recipient, aesKey) {
  return new Promise((resolve, reject) => {  // added promise wrapper to go back here after the function finishes
    try {
      console.log(`request public key for ${recipient}`)

      socket.emit('request-public-key', { username: recipient }, async (response) => {
        if (!response || !response.ok) {
          reject(new Error(response?.error || 'Could not get public key'))
          return;
        }

        console.log(`received public key for ${recipient}`)

        const recipientPublicKey = await importPublicKey(response.publicKey)
        const rawKey = await crypto.subtle.exportKey('raw', aesKey)
        const encryptedKey = await crypto.subtle.encrypt(
          { name: 'RSA-OAEP' },
          recipientPublicKey,
          rawKey
        );

        const encryptedKeyB64 = bytesToB64(new Uint8Array(encryptedKey))

        socket.emit('session-key-exchange', {
          sender: displayName,
          recipient: recipient,
          encryptedSessionKey: encryptedKeyB64,
        });

        console.log(`key sent to ${recipient}, waiting for confirmation...`)

        // this is where we wait for confirmation if recipient got the key
        const timeout = setTimeout(() => {
          reject(new Error('Key exchange timeout'))
        }, 5000); // 5 second timeout

        socket.once('session-key-confirmed', (data) => {
          if (data.recipient === recipient) {
            clearTimeout(timeout);
            console.log(`${recipient} confirmed key receipt`);
            addMsg(`Secure connection established with ${recipient}`, 'sys')
            resolve()  // go back to the function after the recipient confirmed they got the key
          }
        });

        socket.once('session-key-failed', (data) => {
          if (data.recipient === recipient) {
            clearTimeout(timeout);
            reject(new Error(data.reason || 'Key exchange failed'))
          }
        });
      });

    } catch (err) {
      console.error('Key exchange error:', err)
      addMsg(`Failed to exchange key with ${recipient}`, 'sys')
      reject(err)
    }
  });
}
/* ----------------------------------------------------------------------------- 
   WebCrypto state (AES-GCM, 256-bit key) 
   -------------------------------------------------------------------------- */
// let cryptoKey = null
const te = new TextEncoder()
const td = new TextDecoder()


//PHASE 3
// RSA GENERATOR
async function generateRSAkeyFromClient() {
  const keyPair = await window.crypto.subtle.generateKey({
    name: "RSA-OAEP", modulusLength: 2048, //~112 bit security 
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256"
  },
    true, ["encrypt", "decrypt"]); // encrypt -pk, decrypt - sk 

  const spki = await window.crypto.subtle.exportKey("spki", keyPair.publicKey)
  const pubkB64 = bytesToB64(new Uint8Array(spki)) // export public key in Base64 
  console.log("Public Key (Base64):", pubkB64)
  return { keyPair, pubkB64 }
}

// Export private key for local storage
async function exportPrivateKey(privateKey) {
  //  Export private key in pkcs8 format
  const privkcs8 = await window.crypto.subtle.exportKey("pkcs8", privateKey) // gives raw binary 
  return btoa(String.fromCharCode(...new Uint8Array(privkcs8))) // this converts to base64 which is safe for storage
}

// Import public key from Base64
async function importPublicKey(pubkeyB64) {
  const keyData = b64ToBytes(pubkeyB64)
  return await window.crypto.subtle.importKey(
    'spki',
    keyData,
    {
      name: 'RSA-OAEP',
      hash: 'SHA-256'
    },
    true,
    ['encrypt']
  );
}

// Import private key from Base64
async function importPrivateKey(privkeyB64) {
  const keyData = b64ToBytes(privkeyB64)
  return await window.crypto.subtle.importKey(
    'pkcs8',
    keyData,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}

// Load private key from localStorage based on current user
let myPrivateKey = null;
async function loadPrivateKey() {
  if (myPrivateKey) return myPrivateKey

  // Get current username
  const username = displayName || ensureNameLoaded()
  if (!username) {
    console.warn('no username set, cant load private key')
    return null;
  }

  // username-specific key
  let stored = localStorage.getItem(`privateKey_${username}`)

  if (!stored) {
    console.warn('no private key found for', username)
    return null
  }

  try {
    const data = JSON.parse(stored)
    
    // verify the key belongs to this user
    if (data.username !== username) {
      console.error('key mismatch! Stored key is for', data.username, 'but logged in as', username)
      return null
    }
    
    myPrivateKey = await importPrivateKey(data.key)
    console.log(`private key loaded for ${username}`)
    return myPrivateKey
  } catch (err) {
    console.error('failed to load private key:', err)
    return null
  }
}

/* ----------------------------------------------------------------------------- 
   Encrypt / Decrypt (AES-GCM)

   PHASE 3 BIG UPDATE HERE: This function now uses recipient-specific session keys /AES keys - athena
   -------------------------------------------------------------------------- */
async function encryptText(plaintext, recipient) {
// not really needed, but i just want to confirm things
  console.log('encryption debug:')
  console.log('   recipient:', recipient)
  console.log('   ression keys available:', Object.keys(sessionKeys))
  console.log('   has key for recipient?', !!sessionKeys[recipient])

  // heer get the session key for this specific recipient
  const session = sessionKeys[recipient]

  // error handling if no session key found for the two
  if (!session) {
    throw new Error(`no session key for ${recipient}. try sending @${recipient} first.`)
  }

  // logging the key age
  const keyAge = Date.now() - session.timestamp;
  console.log('   Key age:', Math.floor(keyAge / 1000), 'seconds')

  // here we create random IV (initialization vector) for AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12))

  // then we encrypt the message with the session key
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    session.aesKey, // we still encrypt with the regular AES key 
    te.encode(plaintext)
  );


  console.log(`encrypted message for ${recipient}`)

  // we return IV and ciphertext (both needed to decrypt)
  return {
    ivB64: bytesToB64(iv),
    ctB64: bytesToB64(new Uint8Array(ciphertext))
  };
}


// SIMILAR TO ENCRYPT FUNCTION, this one now uses recipient-specific session keys /AES keys 
// function is practically the same as past version, with addition of the sender parameter to identify which session key to use
async function decryptPacket({ ivB64, ctB64 }, sender) {

  // herer get the session key from this sender
  const session = sessionKeys[sender]

  // just in case error happens
  if (!session) {
    throw new Error(`No session key from ${sender}`)
  }

// again we log the key age
  const keyAge = Date.now() - session.timestamp
  console.log('   Key age:', Math.floor(keyAge / 1000), 'seconds')
  console.log('   IV length:', ivB64?.length)
  console.log('   Ciphertext length:', ctB64?.length)

  // convert base64 back to bytes
  const iv = b64ToBytes(ivB64)
  const given_ciphertext = b64ToBytes(ctB64)

  //this is decrypt using the session key
  const plaintextBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    session.aesKey, // aes session key from the sender
    given_ciphertext
  );

  console.log(`decrypted message from ${sender}`)

  // here we convert bytes back to text
  decryptedMessage = td.decode(plaintextBuffer)

  return decryptedMessage
}

/* ----------------------------------------------------------------------------- 
   Socket.IO client + presence data 
   -------------------------------------------------------------------------- */
if (!isSecureContext) alert('WebCrypto needs HTTPS (or localhost). Open the app over HTTPS.')
const socket = io()

let usersOnline = []
let usersAll = []
function updateUserLists(res) {
  if (Array.isArray(res?.online)) usersOnline = res.online
  if (Array.isArray(res?.all)) usersAll = res.all
}

// Update user's own message bubble status
function updateMyMsgStatus(id, newStatus) {
  const el = document.querySelector(`.msg.me[data-mid="${id}"]`)
  if (!el) return
  const statusEl = el.querySelector('.status')
  if (statusEl) {
    statusEl.textContent = newStatus
  } else {
    const meta = el.querySelector('.meta')
    if (meta) meta.innerHTML += ` • <span class="status">${newStatus}</span>`
  }
}


// Auto-register if name already set
socket.on('connect', () => {
  addMsg('Connected to server.', 'sys')
  if (ensureNameLoaded()) {
    socket.emit('register', { username: displayName }, (res) => {
      if (!res?.ok) addMsg(`Auto-register failed: ${res?.error || 'unknown'}`, 'sys')
      else updateUserLists(res)
    })
  }
})

socket.on('presence', (lists) => updateUserLists(lists))

socket.on('history', async (items) => {
  if (!Array.isArray(items)) return
  const readIds = []
  for (const it of items) {
    try {
      const txt = await decryptPacket(it)
      addMsg(`${it.sender || 'Someone'} → ${it.recipient || '—'}: ${txt}`, 'them', it.ts)
      if (it.recipient === displayName && !it.read) readIds.push(it.id)
    } catch {
      addMsg('Unable to decrypt an older message.', 'sys')
    }
  }
  if (readIds.length) socket.emit('mark-read', readIds)
})

socket.on('encrypted-message', async (packet) => {
// debugging logs, see browser console
  console.log('RECEIVED MESSAGE:')
  console.log('   From:', packet.sender)
  console.log('   To:', packet.recipient)
  console.log('   Current user:', displayName);
  console.log('   Is for me?', packet.recipient === displayName)

  try {
    // check if we have session key from sender
    if (!sessionKeys[packet.sender]) {
      console.log(`no session key from ${packet.sender} yet, waiting...`)
      // Wait a bit and try again (in case key is in transit)
      await new Promise(resolve => setTimeout(resolve, 1000))
      if (!sessionKeys[packet.sender]) {
        addMsg(`No session key from ${packet.sender}. Ask them to resend.`, 'sys')
        return;
      }
    }

    // PHASE 3 UPDATE: Decrypt with session key
    const txt = await decryptPacket(packet, packet.sender)


    // Salma Phase 4: verify integrity & authenticity
    let isVerified = false;
    try {
      // recompute the hash of recieved message
      const recomputHash = await crypto.subtle.digest('SHA-256', te.encode(txt));

      // obtain the sender's bublic key from the server
      const pubResp = await new Promise(r => socket.emit('request-public-key', { username: packet.sender }, r));
      if (!pubResp?.publicKey) throw new Error("No public key");
      const publicKey = await crypto.subtle.importKey(
        "spki",
        b64ToBytes(pubResp.publicKey),
        { name: "RSA-PSS", hash: "SHA-256" },
        true,
        ["verify"]
      );

      // verify if the signature matches the sender's bublic key
      if (!packet.signatureB64) throw new Error("Missing signature");

      
      isVerified = await crypto.subtle.verify(
        { name: "RSA-PSS", saltLength: 32 },
        publicKey,
        b64ToBytes(packet.signatureB64),
        recomputHash
      );

    } catch (err) {
      console.error("Verification failed:", err);
    }

    // show message and if its verified or tampered
    const statusText = isVerified ? 'Verified' : 'Tampered';
    addMsg(txt, 'them', packet.ts, statusText);

    // color the bubble red if tampered
    const lastMsgEl = document.querySelector('#messages .msg:last-child');
    if (!isVerified && lastMsgEl) {
      const bubble = lastMsgEl.querySelector('.bubble');
      if (bubble) bubble.style.color = 'red';
    }

    // optionally, set the status in the span exactly like updateMyMsgStatus
    if (lastMsgEl) {
      const statusEl = lastMsgEl.querySelector('.status');
      if (statusEl) {
        statusEl.textContent = statusText;
      }
    }
    
    if (packet.recipient === displayName && !packet.read) {
      socket.emit('mark-read', [packet.id])
    }
  } catch (err) {
    console.error('Decryption or verification failed:', err)
    addMsg(`Failed to decrypt message from ${packet.sender}`, 'sys')
    addMsg(`Error: ${err.message}`, 'sys')

    const messagesEl = document.getElementById('messages')
    if (messagesEl) {
      const div = document.createElement('div')
      div.textContent = `Encrypted message from ${packet.sender} - decryption failed`
      div.style.color = 'red'
      div.style.fontStyle = 'italic'
      messagesEl.appendChild(div)
      messagesEl.scrollTop = messagesEl.scrollHeight
    }
  }
})

  


socket.on('delivery-receipt', ({ id }) => updateMyMsgStatus(id, 'delivered'))
socket.on('read-receipt', ({ id }) => updateMyMsgStatus(id, 'read'))


// This handler receives session key exchange from sender
// basically, encrypted AES key with our public RSA key is sent to us here then we DECRYPT IT with our private RSA key

socket.on('session-key-exchange', async (data) => {
  try {
    console.log(`received key from ${data.sender}`) //make sure we received the key

    // here, retrieve our private key stored in browser
    const privateKey = await loadPrivateKey()
    if (!privateKey) {
      throw new Error('Private key not available')
    }

    // here, we convert received encrypted key from Base64 to bytes for better handling
    const encryptedAESKey = b64ToBytes(data.encryptedSessionKey)

    // here, we now DECRYPT the session key with OUR private RSA key
    const rawKey = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      encryptedAESKey
    );

    // here, we convert raw bytes back to a usable AES key
    const aesKey = await crypto.subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM' }, // type
      true, // extractable
      ['encrypt', 'decrypt'] // the usage for this key- we can encrypt and decrypt
    );

    // here, we save the key to decrypt their messages
    sessionKeys[data.sender] = {
      aesKey: aesKey,
      timestamp: Date.now() // included to know when to renew
    };

    console.log(`key saved for ${data.sender}`)

  } catch (err) {
    console.error('failed to receive key:', err)
  }
});


/* ----------------------------------------------------------------------------- 
   @mention dropdown UX 
   -------------------------------------------------------------------------- */
const mentionMenu = document.getElementById('mentionMenu')

function openMentionMenu(matches, caretRect) {
  mentionMenu.innerHTML = ''
  matches.forEach((name, i) => {
    const item = document.createElement('div')
    item.className = 'mention-item' + (i === 0 ? ' active' : '')
    const tag = document.createElement('span')
    tag.textContent = name
    const status = document.createElement('span')
    status.className = 'mention-tag'
    status.textContent = usersOnline.includes(name) ? 'online' : 'offline'
    item.appendChild(tag)
    item.appendChild(status)
    item.addEventListener('mousedown', (e) => { e.preventDefault(); chooseMention(name) })
    mentionMenu.appendChild(item)
  })
  const { top, left, height } = caretRect
  mentionMenu.style.top = `${top + height + 6}px`
  mentionMenu.style.left = `${left}px`
  mentionMenu.hidden = matches.length === 0
}
function closeMentionMenu() {
  mentionMenu.hidden = true
  mentionMenu.innerHTML = ''
}

async function chooseMention(name) {
  const input = document.getElementById('textInput')
  const { value, selectionStart } = input
  const seg = findAtSegment(value, selectionStart)
  if (!seg) return closeMentionMenu()
  const before = value.slice(0, seg.start)
  const after = value.slice(seg.end)
  const newVal = before + '@' + name + ' ' + after
  input.value = newVal
  const cursor = (before + '@' + name + ' ').length
  input.setSelectionRange(cursor, cursor)
  await setRecipient(name)
  closeMentionMenu()
  input.focus()
}

function findAtSegment(str, caret) {
  let i = caret - 1
  while (i >= 0 && !/\s/.test(str[i])) i--
  const segStart = i + 1
  if (str[segStart] !== '@') return null
  const segEnd = caret
  const query = str.slice(segStart + 1, segEnd)
  return { start: segStart, end: segEnd, query }
}

function caretClientRect(input) {
  const div = document.createElement('div')
  const style = getComputedStyle(input)
  for (const prop of [
    'fontFamily', 'fontSize', 'fontWeight', 'whiteSpace', 'letterSpacing', 'textTransform',
    'paddingLeft', 'paddingRight', 'paddingTop', 'paddingBottom', 'borderLeftWidth', 'borderTopWidth',
    'boxSizing', 'width'
  ]) div.style[prop] = style[prop]
  div.style.position = 'absolute'
  div.style.visibility = 'hidden'
  div.style.top = input.offsetTop + 'px'
  div.style.left = input.offsetLeft + 'px'
  div.textContent = input.value.slice(0, input.selectionStart)
  document.body.appendChild(div)
  const rect = div.getBoundingClientRect()
  const inputRect = input.getBoundingClientRect()
  const res = { top: inputRect.top, left: rect.right, height: inputRect.height }
  document.body.removeChild(div)
  return res
}

/* ----------------------------------------------------------------------------- 
   Wire DOM events 
   -------------------------------------------------------------------------- */
document.addEventListener('DOMContentLoaded', async () => {
  if (window._wired) return
  window._wired = true

  // PHASE 3 UPDATE: private key is loaded after username set
  // For chat page, username comes from server
  const displayNameEl = document.getElementById('displayName')
  if (displayNameEl && displayNameEl.textContent) {
    displayName = displayNameEl.textContent.trim()
    console.log('Username from page:', displayName)
  }

  // Load private key for this user and debugs
  await loadPrivateKey()
  if (myPrivateKey) {
    console.log('Private key loaded for', displayName)
  } else {
    console.warn('No private key found for', displayName)
  }

  // phase 3: here we load our private key from local storage when the client starts
  await loadPrivateKey()
  if (myPrivateKey) {
    console.log('private key loaded from local storage')
  }

  const setKeyButton = document.getElementById('setKeyButton')
  const keyInputField = document.getElementById('keyInputField')
  const setNameButton = document.getElementById('setNameButton')
  const nameInputField = document.getElementById('nameInputField')
  const messageInputField = document.getElementById('messageInputField')
  const chatForm = document.getElementById('chatForm')

  if (setKeyButton && keyInputField && setNameButton && nameInputField && messageInputField && chatForm) {
    setKeyButton.addEventListener('click', async () => {
      const b64 = (keyInputField.value || '').trim()
      if (!b64) return
      try { await setKeyFromB64(b64); keyInputField.value = '' }
      catch (err) { alert(err.message || String(err)) }
    })

    setNameButton.addEventListener('click', () => {
      try { setDisplayName(nameInputField.value); nameInputField.value = '' }
      catch (err) { alert(err.message || String(err)) }
    })

    if (ensureNameLoaded()) addMsg(`Using name: ${displayName}`, 'sys')
    if (ensureRecipientLoaded()) addMsg(`Using recipient: ${currentRecipient}`, 'sys')

    messageInputField.addEventListener('input', () => {
      const seg = findAtSegment(messageInputField.value, messageInputField.selectionStart)
      if (!seg) return closeMentionMenu()
      const query = seg.query.toLowerCase()
      const on = usersOnline.filter(u => u.toLowerCase().startsWith(query))
      const off = usersAll.filter(u => !usersOnline.includes(u) && u.toLowerCase().startsWith(query))
      const matches = [...on, ...off].slice(0, 20)
      if (matches.length === 0) return closeMentionMenu()
      const caretRect = caretClientRect(messageInputField)
      openMentionMenu(matches, caretRect)
    })

    messageInputField.addEventListener('keydown', (e) => {
      if (mentionMenu.hidden) return
      const items = Array.from(mentionMenu.querySelectorAll('.mention-item'))
      const idx = items.findIndex(x => x.classList.contains('active'))
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        const next = (idx + 1) % items.length
        items.forEach(x => x.classList.remove('active'))
        items[next].classList.add('active')
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        const prev = (idx - 1 + items.length) % items.length
        items.forEach(x => x.classList.remove('active'))
        items[prev].classList.add('active')
      } else if (e.key === 'Enter' || e.key === 'Tab') {
        const active = items[idx >= 0 ? idx : 0]
        if (active) {
          e.preventDefault()
          chooseMention(active.firstChild.textContent)
        }
      } else if (e.key === 'Escape') {
        closeMentionMenu()
      }
    })

    document.addEventListener('click', (e) => {
      if (!mentionMenu.hidden && !mentionMenu.contains(e.target)) closeMentionMenu()
    })

    chatForm.addEventListener('submit', async (e) => {
      e.preventDefault()
      const text = (messageInputField.value || '').trim()
      if (!text) return

      if (!socket?.connected) return alert('Not connected.')
      if (!ensureNameLoaded()) return alert('Set your display name first.')
      // if (!(await ensureKeyLoaded())) return alert('Set the shared key first.')
      // for phase 3, we dont need this because it's already automatic!

      const parsed = parseAtRecipient(text)
      let recipient = parsed?.recipient || ensureRecipientLoaded()
      const cleanText = parsed?.plain || text
      if (!recipient) return alert('Add a recipient by typing @name in the message.')

      try {
        // PHASE 3 UPDATE for packet: added recipient parameter to know which keys to use
        const packet = await encryptText(cleanText, recipient)
        const nowIso = new Date().toISOString()
        const tmpId = 'tmp-' + Date.now().toString(36) + Math.random().toString(36).slice(2)
        addMsg(`${displayName} → ${recipient}: ${cleanText}`, 'me', nowIso, 'Sent', tmpId)

        socket.emit('encrypted-message', { sender: displayName, recipient, ...packet , ts: nowIso}, (ack) => {
          if (!ack?.ok) {
            updateMyMsgStatus(tmpId, 'failed')
            return
          }
          const el = document.querySelector(`.msg.me[data-mid="${tmpId}"]`)
          if (el) el.dataset.mid = ack.id
          updateMyMsgStatus(ack.id, ack.delivered ? 'delivered' : 'Sent')
        })

        messageInputField.value = ''
        messageInputField.focus()
      } catch (err) {
        console.error('[secure-im] submit error:', err)
        alert(err.message || String(err))
      }
    })

    // ensureKeyLoaded().then(() => { if (cryptoKey) addMsg('Key loaded from session (ready).', 'sys') })
  }

  function parseAtRecipient(text) {
    if (!text.startsWith('@')) return null
    const m = text.match(/^@([A-Za-z0-9_\-\.]{1,32})\s*(.*)$/)
    if (!m) return null
    const [, recipient, rest] = m
    return { recipient, plain: rest.trim() }
  }

  // PHASE 3- athena's work
  // Written to send pk to server during registration // set up RSA! 
  async function submitRegistration(username, password, confirmPassword) {

    // generate RSA key pair on client side
    const { keyPair, pubkB64 } = await generateRSAkeyFromClient()

    // save private key for future decryption
    // basically we export the private key and then save it to browser locally! so we can retrive it later when user logs in.
    localStorage.setItem("privateKey", JSON.stringify({
      username: username,
      key: await exportPrivateKey(keyPair.privateKey) // key now is in base64 format
    }));

    // Send user, pass, and public key to server thru post request. FIND THIS 
    const response = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },// form url, something like this encoded
      // username=username&password=password&confirmpassword=confirmpassword&publicKey=base64string...
      // these are the form fields we are sending to server
      body: new URLSearchParams({
        username: username,
        password: password,
        confirmpassword: confirmPassword,
        publicKey: pubkB64
      })
    });

    if (response.redirected && response.url.includes('/login')) {
      alert('Registration successful! Please log in.')
      window.location.href = '/login'
    } else {
      alert('Registration failed. Please try again.')
    }
  }

  if (document.getElementById('registerForm')) {
    document.getElementById('registerForm').addEventListener('submit', async function (e) {
      e.preventDefault();
      const btn = this.querySelector('button')
      btn.textContent = 'Generating keys...'
      btn.disabled = true
      await submitRegistration(this.username.value, this.password.value, this.confirmpassword.value)
    });
  }

  window.setDisplayName = setDisplayName
  window.setRecipient = setRecipient
  // submitRegistration is used in registration page to send client side created RSA pk to server.
  window.submitRegistration = submitRegistration

  // phase 3 chat phase handlers!
  const usersEl = document.getElementById('users')
  const sendBtn = document.getElementById('sendButton')
  const msgInput = document.getElementById('messageInput')
  const chatWithEl = document.getElementById('chatWith')
  const messagesEl = document.getElementById('messages')

  if (usersEl && sendBtn && msgInput) {
    console.log('Chat interface detected')

    // When user clicks on a name in sidebar
    usersEl.addEventListener('click', async (e) => {
      const div = e.target.closest('.user')
      if (!div) return

      const username = div.dataset.username

      // PHASE 3: This initializes the session key!
      await setRecipient(username)

      // Update UI
      if (chatWithEl) chatWithEl.textContent = "You are sending messages to: " + username
      if (messagesEl) messagesEl.innerHTML = ""

      console.log(`Session key initialized for ${username}`)
    });

    // When user clicks Send button
    sendBtn.onclick = async () => {
      if (!currentRecipient) return alert("Select a user first")

      const text = msgInput.value.trim()
      if (!text) return

      try {

        if (!sessionKeys[currentRecipient]) {
          //console.log('No session key, initializing...')
          await initializeSessionKey(currentRecipient)
          // give a small delay to ensure key is delivered
          await new Promise(resolve => setTimeout(resolve, 500))
        }

        // PHASE 3: Encrypt with session key
        const packet = await encryptText(text, currentRecipient)

        // phase 4
        const encoder = new TextEncoder();
        const msgData = encoder.encode(text);
        const msgHash = await crypto.subtle.digest('SHA-256', msgData);

        // load sender's private key 
        let privB64;
        const key1 = localStorage.getItem(`privateKey_${displayName}`);
        const key2 = localStorage.getItem('privateKey');
        const stored = key1 || key2;
        if (!stored) throw new Error("Private key missing — re-register");
        try {
          privB64 = JSON.parse(stored).key;
        } catch {
          privB64 = JSON.parse(stored); 
        }

        // import sender's private key to sign with it
        const privateKey = await crypto.subtle.importKey(
          "pkcs8",
          b64ToBytes(privB64),
          { name: "RSA-PSS", hash: "SHA-256" },
          false,
          ["sign"]
        )

        // sign the message with the sender's private key
        const signature = await crypto.subtle.sign(
          { name: "RSA-PSS", saltLength: 32 },
          privateKey,
          msgHash
        )

        const signatureB64 = bytesToB64(new Uint8Array(signature))

        // generate temporary ID for UI
        const tmpId = 'tmp-' + Date.now().toString(36) + Math.random().toString(36).slice(2)
        addMsg(`You: ${text}`, 'me', new Date().toISOString(), 'Sent', tmpId)

        const nowIso = new Date().toISOString()
        
        socket.emit("encrypted-message", {
          sender: displayName,
          recipient: currentRecipient,
          ivB64: packet.ivB64,
          ctB64: packet.ctB64,
          signatureB64: signatureB64,
          mid: tmpId,
          ts: nowIso
        })

        msgInput.value = ""

      } catch (err) {
        console.error('Send error:', err);
        alert(err.message || 'Failed to send message');
      }
    }

  }
})
