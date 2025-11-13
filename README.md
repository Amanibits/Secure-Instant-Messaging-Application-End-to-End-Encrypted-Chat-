# 🔐 Secure Instant Messaging — Phase 1 & Phase 2

A secure real-time messaging application using **AES-GCM encryption in the browser**, **no plaintext stored on the server**, and **direct messaging via @username** with **delivery + read receipts**.

---

## System Overview

| Layer | Responsibility |
|------|----------------|
| Client (Browser) | Encrypts/decrypts messages using WebCrypto (AES-GCM). Displays UI. |
| Server (Node.js + Socket.IO) | Relays encrypted messages, stores ciphertext history, tracks online presence. |
| Storage | In-memory array storing **only ciphertext + metadata** (no plaintext, no keys). |

> **The server never sees plaintext or encryption keys.**  
> Only `{ ivB64, ctB64 }` ciphertext blobs <unreadable> are stored.

---

## Features

### Phase 1 (Complete)
- AES-256-GCM symmetric encryption in browser
- Shared Base64 key manually entered by users
- Real-time messaging via WebSockets
- Server stores only ciphertext

### Phase 2 (Complete)
- Users set **display names**
- Direct messaging using **`@username`**
- Online/offline **presence list**
- **Message history** restored on reconnect
- **Delivery status:** `sent`, `delivered`
- **Read status:** `read` once the message is decrypted by recipient

### Phase 3 (Ongoing)
- MongoDB set up to store user and public keys (no message history)

---

## Tech Stack

| Component | Technology |
|----------|------------|
| Server | Node.js + Express + Socket.IO |
| Transport | **HTTPS** (self-signed for local dev) |
| Crypto | **WebCrypto API (AES-GCM 256-bit)** — in browser |
| UI | HTML + CSS (no frameworks) |

---

## Project Structure

```bash
project/
├─ server.js
├─ certs/
│  ├─ cert.pem
│  └─ key.pem
└─ public/
   ├─ index.html
   ├─ client.js
   └─ styles.css

```
---

## How to Run:

```bash
### 1) Install Dependencies AND MongoDB driver
npm install
npm install mongodb


2) Generate HTTPS Certificates (Only if certs/ does not exist)
mkdir certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout certs/key.pem -out certs/cert.pem -days 365

Press Enter for all prompts.

3) Start the Secure Server
node server.js

4) Open the Application
Visit: https://localhost:3000
and https://YOUR_LOCAL_MACHINE_IP:3000

You can open as many tabs and form different users.
Browser will warn about "Not Secure" — click Advanced → Proceed


Using the App

Step 1 — Set Your Username
Enter a name (e.g., amani, zainab)
→ Click Set Name

Step 2 — Enter the Shared AES Key
All users must paste the same Base64 key.
Generate a fresh key (optional or lazy way) in browser console:
btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))))

Step 3 — Send a Direct Message
Format:
@username your message here
Example: @amani are you online?

```
---
Message Status Indicators
Status | Meaning
sending… | Encrypting + sending to server
sent | Server stored ciphertext (recipient offline)
delivered |Recipient is online and received it
read |	Recipient opened and decrypted the message

---
Security Notes <Flow>:
Encryption never leaves the client
Server does not hold keys
Server cannot decrypt stored messages
In-memory message storage = no SQL or NoSQL yet # Secure-Instant-Messaging-Application-End-to-End-Encrypted-Chat-
 
---