// Amani's part
// -----------------------------------------------------------------------------
// ROLE OF THIS FILE
//   • Owns the key (WebCrypto AES-GCM) and does all encrypt/decrypt in-browser
//   • Talks to server via Socket.IO with ciphertext only
//   • Renders UI, @mention recipient picker, timestamps, and message status
//
// DATA FLOW (browser):
//   plaintext --AES-GCM--> {iv, ciphertext}  ---> server
//   server stores {sender, recipient, ivB64, ctB64, ts, delivered, read}
//
// STATUS MODEL (for “me” bubbles):
//   sending… → (ack) sent | delivered → (read-receipt) read
//   • sent: stored server-side but recipient offline
//   • delivered: recipient device received it (online)
//   • read: the recipient rendered it (client emitted mark-read)
//
//  UPDATES:
// - Manual AES generation removed (user pastes Base64 32-byte key), update to automatically generate
// 
// 
// -----------------------------------------------------------------------------

/* -----------------------------------------------------------------------------
   Small UI helper for blinking bubbles into the log
   addMsg(text, cls, ts?, status?, id?)
   -------------------------------------------------------------------------- */

/* -----------------------------------------------------------------------------
   Small UI helper for blinking bubbles into the log
   addMsg(text, cls, ts?, status?, id?)
   -------------------------------------------------------------------------- */

function addMsg(text, cls = 'sys', ts /* optional ISO string */, status /* optional string */, id /* optional mid */) {
  const logEl = document.getElementById('log')
  if (!logEl) { console.warn('[secure-im] #log missing'); return }

  const div = document.createElement('div')
  div.className = `msg ${cls}`
  if (id) div.dataset.mid = id // allow later status updates by id

  const main = document.createElement('div')
  main.textContent = text
  div.appendChild(main)

  // timestamp + status (tiny)
  if (ts || status) {
    const meta = document.createElement('span')
    meta.className = 'meta'
    let metaText = ''
    if (ts) metaText += formatTs(ts)
    if (ts && status) metaText += ' • '
    if (status) metaText += status
    meta.textContent = metaText
    div.appendChild(meta)
  }

  logEl.appendChild(div)
  logEl.scrollTop = logEl.scrollHeight
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
    socket.emit('register', displayName, (res) => {
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
   Recipient state (set when user types @… and chooses a name) 
   -------------------------------------------------------------------------- */
let currentRecipient = null

function setRecipient(name) {
  const n = (name || '').trim()
  if (!n) throw new Error('Recipient cannot be empty.')
  if (n.length > 32) throw new Error('Recipient too long (max 32 chars).')
  currentRecipient = n
  sessionStorage.setItem('recipient', n)
  addMsg(`Recipient set to: ${n}`, 'sys')
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

/* ----------------------------------------------------------------------------- 
   WebCrypto state (AES-GCM, 256-bit key) 
   -------------------------------------------------------------------------- */
let cryptoKey = null
const te = new TextEncoder()
const td = new TextDecoder()

async function setKeyFromB64(b64) {
  const raw = b64ToBytes(b64)
  if (raw.length !== 32) throw new Error(`Key must decode to 32 bytes (got ${raw.length})`)
  cryptoKey = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
  sessionStorage.setItem('sharedKeyB64', normalizeB64(b64))
  addMsg('Shared key set for this session.', 'sys')
}

async function ensureKeyLoaded() {
  if (cryptoKey) return cryptoKey
  const cached = sessionStorage.getItem('sharedKeyB64')
  if (cached) {
    try { await setKeyFromB64(cached) }
    catch (e) { console.warn('[secure-im] stored key invalid; paste again', e) }
  }
  return cryptoKey
}

/* ----------------------------------------------------------------------------- 
   Encrypt / Decrypt (AES-GCM) 
   -------------------------------------------------------------------------- */
async function encryptText(plaintext) {
  await ensureKeyLoaded()
  if (!cryptoKey) throw new Error('No shared key set.')
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, te.encode(plaintext)))
  return { ivB64: bytesToB64(iv), ctB64: bytesToB64(ct) }
}
async function decryptPacket({ ivB64, ctB64 }) {
  await ensureKeyLoaded()
  if (!cryptoKey) throw new Error('No shared key set.')
  const iv = b64ToBytes(ivB64)
  const ct = b64ToBytes(ctB64)
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ct)
  return td.decode(ptBuf)
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
  const meta = el.querySelector('.meta')
  if (!meta) return
  const parts = meta.textContent.split('•')
  const timePart = parts[0].trim()
  meta.textContent = timePart ? `${timePart} • ${newStatus}` : newStatus
}

// Auto-register if name already set
socket.on('connect', () => {
  addMsg('Connected to server.', 'sys')
  if (ensureNameLoaded()) {
    socket.emit('register', displayName, (res) => {
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
  try {
    const txt = await decryptPacket(packet)
    addMsg(`${packet.sender || 'Someone'} → ${packet.recipient || '—'}: ${txt}`, 'them', packet.ts)
    if (packet.recipient === displayName && !packet.read) {
      socket.emit('mark-read', [packet.id])
    }
  } catch {
    addMsg('Received message but decryption failed.', 'sys')
  }
})

socket.on('delivery-receipt', ({ id }) => updateMyMsgStatus(id, 'delivered'))
socket.on('read-receipt', ({ id }) => updateMyMsgStatus(id, 'read'))

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

function chooseMention(name) {
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
  setRecipient(name)
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
document.addEventListener('DOMContentLoaded', () => {
  if (window._wired) return
  window._wired = true

  const setKeyButton = document.getElementById('setKeyButton')
  const keyInputField = document.getElementById('keyInputField')
  const setNameButton = document.getElementById('setNameButton')
  const nameInputField = document.getElementById('nameInputField')
  const messageInputField = document.getElementById('messageInputField')
  const chatForm = document.getElementById('chatForm')

  if (!chatForm || !messageInputField || !keyInputField || !setKeyButton || !nameInputField || !setNameButton) {
    console.error('[secure-im] Missing DOM elements')
    return
  }

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
    if (!(await ensureKeyLoaded())) return alert('Set the shared key first.')

    const parsed = parseAtRecipient(text)
    let recipient = parsed?.recipient || ensureRecipientLoaded()
    const cleanText = parsed?.plain || text
    if (!recipient) return alert('Add a recipient by typing @name in the message.')

    try {
      const packet = await encryptText(cleanText)
      const nowIso = new Date().toISOString()
      const tmpId = 'tmp-' + Date.now().toString(36) + Math.random().toString(36).slice(2)
      addMsg(`${displayName} → ${recipient}: ${cleanText}`, 'me', nowIso, 'sending…', tmpId)

      socket.emit('encrypted-message', { sender: displayName, recipient, ...packet }, (ack) => {
        if (!ack?.ok) {
          updateMyMsgStatus(tmpId, 'failed')
          return
        }
        const el = document.querySelector(`.msg.me[data-mid="${tmpId}"]`)
        if (el) el.dataset.mid = ack.id
        updateMyMsgStatus(ack.id, ack.delivered ? 'delivered' : 'sent')
      })

      messageInputField.value = ''
      messageInputField.focus()
    } catch (err) {
      console.error('[secure-im] submit error:', err)
      alert(err.message || String(err))
    }
  })

  ensureKeyLoaded().then(() => { if (cryptoKey) addMsg('Key loaded from session (ready).', 'sys') })
})

function parseAtRecipient(text) {
  if (!text.startsWith('@')) return null
  const m = text.match(/^@([A-Za-z0-9_\-\.]{1,32})\s*(.*)$/)
  if (!m) return null
  const [, recipient, rest] = m
  return { recipient, plain: rest.trim() }
}

window.setDisplayName = setDisplayName
window.setRecipient = setRecipient
