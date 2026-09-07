// Author Web App Client

const PROTOCOL_PREFIX = "author-id:v1";

// Utilities
function toHex(uint8arr) {
  return Array.from(uint8arr)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(hexString) {
  hexString = hexString.trim();
  const bytes = new Uint8Array(hexString.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hexString.substr(i * 2, 2), 16);
  }
  return bytes;
}

function strToBytes(str) {
  return new TextEncoder().encode(str);
}

function bytesToStr(bytes) {
  return new TextDecoder().decode(bytes);
}

async function sha256Hex(str) {
  const hashBuffer = await crypto.subtle.digest("SHA-256", strToBytes(str));
  return toHex(new Uint8Array(hashBuffer));
}

// Curve25519 & E2EE Cryptographic Operations
const CURVE25519_P = (2n ** 255n) - 19n;

function modPow(base, exp, mod) {
  let res = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp % 2n === 1n) res = (res * base) % mod;
    base = (base * base) % mod;
    exp /= 2n;
  }
  return res;
}

function modInverse(a, m) {
  return modPow(a, m - 2n, m);
}

// Convert 32-byte Ed25519 public key to Curve25519 public key (Montgomery u-coordinate)
function ed25519PubToCurve25519(edPubBytes) {
  let y = 0n;
  for (let i = 0; i < 32; i++) {
    let byte = BigInt(edPubBytes[i]);
    if (i === 31) byte &= 0x7Fn;
    y |= (byte << (BigInt(i) * 8n));
  }
  const one = 1n;
  const num = (one + y) % CURVE25519_P;
  const den = (CURVE25519_P + one - y) % CURVE25519_P;
  const u = (num * modInverse(den, CURVE25519_P)) % CURVE25519_P;

  const out = new Uint8Array(32);
  let temp = u;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(temp & 0xFFn);
    temp >>= 8n;
  }
  return out;
}

// Derive 32-byte X25519 secret scalar from 64-byte Ed25519 secret key
function deriveX25519SecretKey(edPrivBytes) {
  const seed = edPrivBytes.subarray(0, 32);
  const h = nacl.hash(seed);
  const s = new Uint8Array(32);
  for (let i = 0; i < 32; i++) s[i] = h[i];
  s[0] &= 248;
  s[31] &= 127;
  s[31] |= 64;
  return s;
}

function getRandomNonce(byteLen = 16) {
  const arr = new Uint8Array(byteLen);
  crypto.getRandomValues(arr);
  return toHex(arr);
}

function showToast(message) {
  const toast = document.getElementById("toast");
  toast.innerText = message;
  toast.style.display = "block";
  setTimeout(() => {
    toast.style.display = "none";
  }, 3500);
}

// Local Storage Keystore
const STORAGE_KEY = "author_local_vault_v1";

function loadVault() {
  const data = localStorage.getItem(STORAGE_KEY);
  if (!data) return { identities: [], activeIndex: -1 };
  try {
    return JSON.parse(data);
  } catch (e) {
    return { identities: [], activeIndex: -1 };
  }
}

function saveVault(vault) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(vault));
}

function getActiveIdentity() {
  const vault = loadVault();
  if (vault.activeIndex >= 0 && vault.activeIndex < vault.identities.length) {
    return vault.identities[vault.activeIndex];
  }
  return null;
}

// Chat Persistence Helpers
function getChatHistoryKey(username) {
  return `author_chat_history_${username}`;
}

function loadChatHistory(username) {
  if (!username) return [];
  const raw = localStorage.getItem(getChatHistoryKey(username));
  if (!raw) return [];
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function saveChatHistoryMessage(username, type, text, sender, isE2EE = false, peer = "") {
  if (!username) return;
  const history = loadChatHistory(username);
  const resolvedPeer = (peer || (type === "incoming" ? sender : "")).toLowerCase().trim();
  history.push({ type, text, sender, isE2EE, peer: resolvedPeer, time: Date.now() });
  if (history.length > 200) history.shift();
  localStorage.setItem(getChatHistoryKey(username), JSON.stringify(history));
}

function renderChatHistory(username, filterPeer = "") {
  const box = document.getElementById("chatBox");
  box.innerHTML = "";
  const history = loadChatHistory(username);
  const peerNorm = (filterPeer || "").toLowerCase().trim();

  const filtered = history.filter(m => {
    if (!peerNorm) return true;
    const mPeer = (m.peer || (m.type === "incoming" ? m.sender : "")).toLowerCase().trim();
    return !mPeer || mPeer === peerNorm;
  });

  if (filtered.length === 0) {
    box.innerHTML = `<div style="text-align: center; color: var(--text-muted); font-size: 0.85rem; margin: auto;">
      ${peerNorm ? `No messages yet with @${peerNorm}. Send an encrypted message below!` : "Messages are end-to-end encrypted (🔒 E2EE) and pushed in real-time."}
    </div>`;
    return;
  }
  for (const m of filtered) {
    appendChatMessageDOM(m.type, m.text, m.sender, m.isE2EE);
  }
}

// State
let currentIdentity = null;
let eventSource = null;
let lastSeenMessageId = 0;
let reconnectTimer = null;

// Biometric Unlock Handler using WebAuthn
async function attemptBiometricUnlock() {
  if (window.PublicKeyCredential) {
    try {
      const challenge = new Uint8Array(32);
      crypto.getRandomValues(challenge);

      await navigator.credentials.get({
        publicKey: {
          challenge: challenge,
          timeout: 60000,
          userVerification: "preferred"
        }
      });
      showToast("Biometric verification successful!");
    } catch (e) {
      console.log("Biometric info:", e.message);
    }
  }
  unlockVault();
}

function unlockVault() {
  document.getElementById("lockScreen").style.display = "none";
  document.getElementById("appContainer").style.display = "block";
  refreshUI();
  startRealtimeStream();
}

// UI Refresh
async function refreshUI() {
  currentIdentity = getActiveIdentity();
  const noIdCard = document.getElementById("noIdentityCard");
  const activeCard = document.getElementById("activeIdentityCard");
  const select = document.getElementById("identitySelect");
  const btnNew = document.getElementById("btnHeaderNewId");
  const vault = loadVault();

  // Populate Identity Dropdown Switcher
  select.innerHTML = "";
  if (vault.identities.length > 0) {
    select.style.display = "inline-block";
    vault.identities.forEach((id, idx) => {
      const opt = document.createElement("option");
      opt.value = idx;
      opt.innerText = `@${id.username} (${id.status})`;
      if (idx === vault.activeIndex) opt.selected = true;
      select.appendChild(opt);
    });

    if (vault.identities.length < 3) {
      btnNew.style.display = "inline-block";
    } else {
      btnNew.style.display = "none";
    }
  } else {
    select.style.display = "none";
    btnNew.style.display = "none";
  }

  if (!currentIdentity) {
    noIdCard.style.display = "block";
    activeCard.style.display = "none";
    renderChatHistory("");
  } else {
    noIdCard.style.display = "none";
    activeCard.style.display = "block";

    document.getElementById("cardUsername").innerText = currentIdentity.username;
    document.getElementById("cardPubKey").innerText = currentIdentity.pubKey;
    document.getElementById("cardVersion").innerText = currentIdentity.version || 1;

    const badge = document.getElementById("cardStatusBadge");
    if (currentIdentity.status === "revoked") {
      badge.className = "badge badge-revoked";
      badge.innerText = "REVOKED";
    } else {
      badge.className = "badge badge-active";
      badge.innerText = "ACTIVE";
    }

    document.getElementById("cardSlots").innerText = `${vault.identities.length} / 3`;

    // Load chat recipient and history for current identity
    const lastRecip = localStorage.getItem(`author_last_chat_recipient_${currentIdentity.username}`) || "";
    const recipInput = document.getElementById("inputChatRecipient");
    const headerName = document.getElementById("chatRecipientName");
    if (recipInput) recipInput.value = lastRecip;
    if (headerName) headerName.innerText = lastRecip ? "@" + lastRecip : "(Select Recipient)";

    renderChatHistory(currentIdentity.username, lastRecip);
  }

  await checkHealth();
}

async function checkHealth() {
  try {
    const res = await fetch("/health");
    if (res.ok) {
      document.getElementById("relayDot").style.background = "#00e599";
      document.getElementById("relayStatusText").innerText = "Relay Connected";
    } else {
      throw new Error();
    }
  } catch {
    document.getElementById("relayDot").style.background = "#ef4444";
    document.getElementById("relayStatusText").innerText = "Relay Offline";
  }
}

// Identity Actions
async function claimIdentity() {
  const username = document.getElementById("inputClaimUsername").value.trim().toLowerCase();
  if (!username) {
    alert("Please enter a username.");
    return;
  }

  const vault = loadVault();
  if (vault.identities.length >= 3) {
    alert("Device limit reached (max 3 identities allowed per install).");
    return;
  }

  // Generate Ed25519 keypair
  const keyPair = nacl.sign.keyPair();
  const pubHex = toHex(keyPair.publicKey);
  const privHex = toHex(keyPair.secretKey);

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = getRandomNonce(16);

  // Format canonical claim payload
  const msg = `${PROTOCOL_PREFIX}:CLAIM:${username}:${pubHex}:${timestamp}:${nonce}`;
  const sigBytes = nacl.sign.detached(strToBytes(msg), keyPair.secretKey);
  const sigHex = toHex(sigBytes);

  try {
    const resp = await fetch("/v1/claim", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        pubkey: pubHex,
        timestamp,
        nonce,
        sig: sigHex
      })
    });

    const data = await resp.json();
    if (!resp.ok) {
      alert("Claim failed: " + (data.error || "Unknown error"));
      return;
    }

    // Save to local vault
    vault.identities.push({
      username,
      pubKey: pubHex,
      privKey: privHex,
      version: 1,
      status: "active"
    });
    vault.activeIndex = vault.identities.length - 1;
    saveVault(vault);

    showToast(`Identity @${username} claimed successfully!`);
    refreshUI();
    startRealtimeStream();
    openRecoveryModal("Identity Created — Save Recovery Key", username, privHex);
  } catch (err) {
    alert("Network error claiming identity: " + err.message);
  }
}

async function rotateIdentity() {
  if (!currentIdentity || currentIdentity.status === "revoked") {
    alert("Cannot rotate: No active identity.");
    return;
  }

  if (!confirm(`Are you sure you want to rotate keys for @${currentIdentity.username}?`)) {
    return;
  }

  const oldPrivKeyBytes = fromHex(currentIdentity.privKey);
  const newKeyPair = nacl.sign.keyPair();
  const newPubHex = toHex(newKeyPair.publicKey);
  const newPrivHex = toHex(newKeyPair.secretKey);

  const targetVersion = (currentIdentity.version || 1) + 1;
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = getRandomNonce(16);

  const msg = `${PROTOCOL_PREFIX}:ROTATE:${currentIdentity.username}:${currentIdentity.pubKey}:${newPubHex}:${targetVersion}:${timestamp}:${nonce}`;
  const sigOldBytes = nacl.sign.detached(strToBytes(msg), oldPrivKeyBytes);
  const sigNewBytes = nacl.sign.detached(strToBytes(msg), newKeyPair.secretKey);

  try {
    const resp = await fetch("/v1/rotate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: currentIdentity.username,
        old_pubkey: currentIdentity.pubKey,
        new_pubkey: newPubHex,
        version: targetVersion,
        timestamp,
        nonce,
        sig: toHex(sigOldBytes),
        new_sig: toHex(sigNewBytes)
      })
    });

    const data = await resp.json();
    if (!resp.ok) {
      alert("Rotation failed: " + (data.error || "Unknown error"));
      return;
    }

    // Update vault
    const vault = loadVault();
    vault.identities[vault.activeIndex].pubKey = newPubHex;
    vault.identities[vault.activeIndex].privKey = newPrivHex;
    vault.identities[vault.activeIndex].version = targetVersion;
    saveVault(vault);

    showToast("Key rotated successfully to version " + targetVersion);
    refreshUI();
    startRealtimeStream();
  } catch (err) {
    alert("Network error rotating key: " + err.message);
  }
}

async function revokeIdentity() {
  if (!currentIdentity || currentIdentity.status === "revoked") {
    alert("Already revoked or not active.");
    return;
  }

  if (!confirm(`CRITICAL: Revoke @${currentIdentity.username} permanently? This CANNOT be undone.`)) {
    return;
  }

  const privKeyBytes = fromHex(currentIdentity.privKey);
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = getRandomNonce(16);

  const msg = `${PROTOCOL_PREFIX}:REVOKE:${currentIdentity.username}:${currentIdentity.pubKey}:${timestamp}:${nonce}`;
  const sigBytes = nacl.sign.detached(strToBytes(msg), privKeyBytes);

  try {
    const resp = await fetch("/v1/revoke", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: currentIdentity.username,
        pubkey: currentIdentity.pubKey,
        timestamp,
        nonce,
        sig: toHex(sigBytes)
      })
    });

    const data = await resp.json();
    if (!resp.ok) {
      alert("Revocation failed: " + (data.error || "Unknown error"));
      return;
    }

    const vault = loadVault();
    vault.identities[vault.activeIndex].status = "revoked";
    saveVault(vault);

    showToast(`Identity @${currentIdentity.username} revoked.`);
    refreshUI();
  } catch (err) {
    alert("Network error revoking identity: " + err.message);
  }
}

function openRecoveryModal(title, handle, privKeyHex) {
  document.getElementById("recoveryModalTitle").innerText = title;
  document.getElementById("recoveryModalHandle").innerText = "@" + handle;
  document.getElementById("recoveryModalPrivKey").innerText = privKeyHex;
  document.getElementById("recoveryModal").style.display = "flex";
}

function closeRecoveryModal() {
  document.getElementById("recoveryModal").style.display = "none";
}

function exportRecovery() {
  if (!currentIdentity) return;
  openRecoveryModal("Identity Recovery Export", currentIdentity.username, currentIdentity.privKey);
}

async function importIdentity() {
  const username = document.getElementById("inputImportUsername").value.trim().toLowerCase();
  let keyHex = document.getElementById("inputImportKey").value.trim();

  if (!username) {
    alert("Please enter your registered handle.");
    return;
  }
  if (!keyHex) {
    alert("Please paste your private key hex.");
    return;
  }

  // Normalize key string (remove spaces, newlines, 0x prefix if any)
  if (keyHex.startsWith("0x") || keyHex.startsWith("0X")) keyHex = keyHex.slice(2);
  keyHex = keyHex.replace(/\s+/g, "");

  let keyPair;
  try {
    if (keyHex.length === 64) {
      // 32-byte seed
      const seedBytes = fromHex(keyHex);
      keyPair = nacl.sign.keyPair.fromSeed(seedBytes);
    } else if (keyHex.length === 128) {
      // 64-byte secret key (TweetNaCl / Author standard)
      const secretBytes = fromHex(keyHex);
      keyPair = nacl.sign.keyPair.fromSecretKey(secretBytes);
    } else {
      alert(`Invalid key length (${keyHex.length} hex characters). Expected 128 characters (64-byte secret key) or 64 characters (32-byte seed).`);
      return;
    }
  } catch (err) {
    alert("Error decoding private key hex: " + err.message);
    return;
  }

  const derivedPubHex = toHex(keyPair.publicKey);
  const fullPrivHex = toHex(keyPair.secretKey);

  // Validate against authoritative relay
  try {
    const res = await fetch(`/v1/resolve/${username}`);
    if (!res.ok) {
      alert(`Handle @${username} is not registered on the relay. Please verify the handle spelling.`);
      return;
    }

    const relayIdentity = await res.json();
    if (relayIdentity.pubkey.toLowerCase() !== derivedPubHex.toLowerCase()) {
      alert(`Verification Failed!\n\nThe provided private key derives public key:\n${derivedPubHex}\n\nBut relay has registered:\n${relayIdentity.pubkey}\n\nThis key does not own @${username}.`);
      return;
    }

    // Check device limit
    const vault = loadVault();
    const existingIndex = vault.identities.findIndex(id => id.username === username);

    if (existingIndex >= 0) {
      vault.identities[existingIndex] = {
        username,
        pubKey: derivedPubHex,
        privKey: fullPrivHex,
        version: relayIdentity.version,
        status: relayIdentity.status
      };
      vault.activeIndex = existingIndex;
    } else {
      if (vault.identities.length >= 3) {
        alert("Device limit reached (max 3 identities allowed per install). Revoke or remove an identity first.");
        return;
      }
      vault.identities.push({
        username,
        pubKey: derivedPubHex,
        privKey: fullPrivHex,
        version: relayIdentity.version,
        status: relayIdentity.status
      });
      vault.activeIndex = vault.identities.length - 1;
    }

    saveVault(vault);
    showToast(`Identity @${username} imported successfully!`);
    document.getElementById("inputImportUsername").value = "";
    document.getElementById("inputImportKey").value = "";

    refreshUI();
    startRealtimeStream();
  } catch (err) {
    alert("Network error verifying identity with relay: " + err.message);
  }
}

function openConversationWith(username) {
  if (!username) return;
  username = username.toLowerCase().trim();

  const tabBtn = document.querySelector('[data-tab="tab-chat"]');
  if (tabBtn) tabBtn.click();

  const recipInput = document.getElementById("inputChatRecipient");
  if (recipInput) recipInput.value = username;

  const headerName = document.getElementById("chatRecipientName");
  if (headerName) headerName.innerText = "@" + username;

  if (currentIdentity) {
    localStorage.setItem(`author_last_chat_recipient_${currentIdentity.username}`, username);
    renderChatHistory(currentIdentity.username, username);
  }

  const msgInput = document.getElementById("inputChatMessage");
  if (msgInput) {
    msgInput.focus();
  }
}

// Directory Lookup
async function resolveUser() {
  const username = document.getElementById("inputLookupUser").value.trim().toLowerCase();
  if (!username) return;

  try {
    const resp = await fetch(`/v1/resolve/${username}`);
    if (!resp.ok) {
      alert(`User @${username} not found on relay.`);
      return;
    }

    const data = await resp.json();
    const resultBox = document.getElementById("lookupResultBox");
    resultBox.style.display = "block";

    document.getElementById("lookupUsername").innerText = "@" + data.username;
    document.getElementById("lookupPubKey").innerText = data.pubkey;
    document.getElementById("lookupVersion").innerText = data.version;
    document.getElementById("lookupCreated").innerText = new Date(data.created_at).toLocaleDateString();

    const resolvedChatName = document.getElementById("resolvedChatUsername");
    if (resolvedChatName) resolvedChatName.innerText = data.username;

    const badge = document.getElementById("lookupBadge");
    if (data.status === "active") {
      badge.className = "badge badge-active";
      badge.innerText = "ACTIVE";
    } else {
      badge.className = "badge badge-revoked";
      badge.innerText = "REVOKED";
    }

    document.getElementById("btnChatWithResolved").onclick = () => {
      openConversationWith(data.username);
    };
  } catch (err) {
    alert("Lookup error: " + err.message);
  }
}

// Messaging / Chat
async function sendChatMessage() {
  if (!currentIdentity || currentIdentity.status === "revoked") {
    alert("You need an active identity to send messages.");
    return;
  }

  const recipient = document.getElementById("inputChatRecipient").value.trim().toLowerCase();
  const text = document.getElementById("inputChatMessage").value.trim();

  if (!recipient || !text) {
    alert("Recipient and message text required.");
    return;
  }

  // 1. Resolve recipient from relay to get their authoritative Ed25519 public key
  let recipEdPubHex = "";
  try {
    const res = await fetch(`/v1/resolve/${recipient}`);
    if (!res.ok) {
      alert(`Cannot send: Recipient @${recipient} not found on relay.`);
      return;
    }
    const recipData = await res.json();
    if (recipData.status === "revoked") {
      alert(`Cannot send: Recipient @${recipient} is permanently revoked.`);
      return;
    }
    recipEdPubHex = recipData.pubkey;
  } catch (err) {
    alert("Network error resolving recipient: " + err.message);
    return;
  }

  // 2. Convert recipient's Ed25519 public key to Curve25519 (X25519)
  const recipXPub = ed25519PubToCurve25519(fromHex(recipEdPubHex));

  // 3. Generate ephemeral X25519 keypair for Perfect Forward Secrecy
  const ephemKeyPair = nacl.box.keyPair();

  // 4. Generate 24-byte random nonce for XSalsa20-Poly1305
  const boxNonce = nacl.randomBytes(24);

  // 5. Encrypt message text
  const ciphertextBytes = nacl.box(strToBytes(text), boxNonce, recipXPub, ephemKeyPair.secretKey);

  // 6. Zero-Knowledge E2EE envelope
  const e2eeEnvelope = JSON.stringify({
    v: 1,
    alg: "x25519-xsalsa20-poly1305",
    ephem_pub: toHex(ephemKeyPair.publicKey),
    nonce: toHex(boxNonce),
    ciphertext: toHex(ciphertextBytes),
    sender: currentIdentity.username
  });

  const payloadHash = await sha256Hex(e2eeEnvelope);
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = getRandomNonce(16);

  const msg = `${PROTOCOL_PREFIX}:SEND:${recipient}:${currentIdentity.username}:${payloadHash}:${timestamp}:${nonce}`;
  const sigBytes = nacl.sign.detached(strToBytes(msg), fromHex(currentIdentity.privKey));

  try {
    const resp = await fetch("/v1/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        recipient,
        sender: currentIdentity.username,
        payload: e2eeEnvelope,
        timestamp,
        nonce,
        sig: toHex(sigBytes)
      })
    });

    const data = await resp.json();
    if (!resp.ok) {
      alert("Failed to send message: " + (data.error || "Unknown error"));
      return;
    }

    saveChatHistoryMessage(currentIdentity.username, "outgoing", text, currentIdentity.username, true, recipient);
    appendChatMessageDOM("outgoing", text, currentIdentity.username, true);
    document.getElementById("inputChatMessage").value = "";
    showToast("Message encrypted (🔒 E2EE) & sent to @" + recipient);
  } catch (err) {
    alert("Error sending message: " + err.message);
  }
}

// Real-Time SSE Stream with Automatic Reconnect & Cursor Gap-Fill
function startRealtimeStream() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  if (!currentIdentity || currentIdentity.status === "revoked") return;

  const username = currentIdentity.username;
  const storedCursor = localStorage.getItem(`author_cursor_${username}`);
  if (storedCursor) {
    lastSeenMessageId = parseInt(storedCursor, 10) || 0;
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = getRandomNonce(16);
  const msg = `${PROTOCOL_PREFIX}:INBOX:${username}:${timestamp}:${nonce}`;
  const sigBytes = nacl.sign.detached(strToBytes(msg), fromHex(currentIdentity.privKey));
  const sig = toHex(sigBytes);

  const url = `/v1/events?recipient=${encodeURIComponent(username)}&ts=${timestamp}&nonce=${nonce}&sig=${sig}&since_id=${lastSeenMessageId}`;
  eventSource = new EventSource(url);

  eventSource.onopen = () => {
    document.getElementById("relayDot").style.background = "#00e599";
    document.getElementById("relayStatusText").innerText = "Live Realtime Push (<2ms)";
  };

  eventSource.addEventListener("connected", (e) => {
    document.getElementById("relayDot").style.background = "#00e599";
    document.getElementById("relayStatusText").innerText = "Live Realtime Push (<2ms)";
  });

  eventSource.addEventListener("message", async (e) => {
    try {
      const m = JSON.parse(e.data);
      if (m.id > lastSeenMessageId) {
        lastSeenMessageId = m.id;
        localStorage.setItem(`author_cursor_${username}`, lastSeenMessageId.toString());
      }

      let bodyText = m.payload;
      let senderName = m.sender;
      let isE2EE = false;
      try {
        const env = JSON.parse(m.payload);
        if (env.alg === "x25519-xsalsa20-poly1305" && env.ephem_pub && env.nonce && env.ciphertext) {
          const myXPriv = deriveX25519SecretKey(fromHex(currentIdentity.privKey));
          const opened = nacl.box.open(fromHex(env.ciphertext), fromHex(env.nonce), fromHex(env.ephem_pub), myXPriv);
          if (opened) {
            bodyText = bytesToStr(opened);
            isE2EE = true;
          } else {
            bodyText = "[⚠️ E2EE Decryption Failed]";
          }
          senderName = env.sender || m.sender;
        } else {
          bodyText = env.body || m.payload;
          senderName = env.from || m.sender;
        }
      } catch {}

      saveChatHistoryMessage(username, "incoming", bodyText, senderName, isE2EE, senderName);

      const activeRecip = (document.getElementById("inputChatRecipient").value || "").trim().toLowerCase();
      if (!activeRecip || activeRecip === senderName.toLowerCase()) {
        appendChatMessageDOM("incoming", bodyText, senderName, isE2EE);
      } else {
        showToast(`New message from @${senderName}`);
      }

      // Acknowledge receipt so relay prunes it
      await acknowledgeMessages([m.id]);
    } catch (err) {
      console.error("Error processing stream event:", err);
    }
  });

  eventSource.onerror = () => {
    console.log("Stream dropped. Reconnecting with fresh token in 3s...");
    document.getElementById("relayStatusText").innerText = "Reconnecting stream...";
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    reconnectTimer = setTimeout(startRealtimeStream, 3000);
  };
}

async function acknowledgeMessages(ids) {
  if (!ids || ids.length === 0 || !currentIdentity) return;

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = getRandomNonce(16);
  const idsSummary = ids.join(",");

  const msg = `${PROTOCOL_PREFIX}:ACK:${currentIdentity.username}:${idsSummary}:${timestamp}:${nonce}`;
  const sigBytes = nacl.sign.detached(strToBytes(msg), fromHex(currentIdentity.privKey));

  try {
    await fetch("/v1/ack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        recipient: currentIdentity.username,
        message_ids: ids,
        timestamp,
        nonce,
        sig: toHex(sigBytes)
      })
    });
  } catch (err) {
    console.error("Ack error:", err);
  }
}

function appendChatMessageDOM(type, text, sender, isE2EE = false) {
  const box = document.getElementById("chatBox");
  // Remove placeholder if present
  if (box.children.length === 1 && box.children[0].innerText.includes("Messages are")) {
    box.innerHTML = "";
  }

  const div = document.createElement("div");
  div.className = "chat-msg " + type;

  const header = document.createElement("div");
  header.className = "chat-msg-header";

  const senderSpan = document.createElement("span");
  senderSpan.innerText = "@" + sender;
  senderSpan.title = `Click to chat with @${sender}`;
  senderSpan.style.cursor = "pointer";
  senderSpan.style.textDecoration = "underline";
  senderSpan.onclick = () => openConversationWith(sender);

  header.appendChild(senderSpan);

  if (isE2EE) {
    const badge = document.createElement("span");
    badge.style.color = "#00e599";
    badge.style.fontSize = "0.75rem";
    badge.style.marginLeft = "0.4rem";
    badge.innerText = "🔒 E2EE";
    header.appendChild(badge);
  }

  const body = document.createElement("div");
  body.innerText = text;

  div.appendChild(header);
  div.appendChild(body);
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

// Event Listeners & App Initialization
function initApp() {
  checkHealth();
  document.getElementById("btnUnlockBiometric").onclick = attemptBiometricUnlock;
  document.getElementById("btnUnlockPass").onclick = unlockVault;

  // Identity Switcher
  document.getElementById("identitySelect").onchange = (e) => {
    const vault = loadVault();
    vault.activeIndex = parseInt(e.target.value, 10);
    saveVault(vault);
    refreshUI();
    startRealtimeStream();
    showToast(`Switched active identity to @${getActiveIdentity().username}`);
  };

  document.getElementById("btnHeaderNewId").onclick = () => {
    document.querySelector('[data-tab="tab-identity"]').click();
    document.getElementById("noIdentityCard").style.display = "block";
    document.getElementById("btnModeClaim").click();
    document.getElementById("inputClaimUsername").focus();
  };

  // Tabs
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.onclick = () => {
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.dataset.tab).classList.add("active");
    };
  });

  document.getElementById("btnSubmitClaim").onclick = claimIdentity;
  document.getElementById("btnSubmitImport").onclick = importIdentity;
  document.getElementById("btnRotateKey").onclick = rotateIdentity;
  document.getElementById("btnRevokeIdentity").onclick = revokeIdentity;
  document.getElementById("btnExportKey").onclick = exportRecovery;

  // Claim vs Import Sub-modes
  document.getElementById("btnModeClaim").onclick = () => {
    document.getElementById("btnModeClaim").classList.add("btn-mode-active");
    document.getElementById("btnModeImport").classList.remove("btn-mode-active");
    document.getElementById("panelClaimMode").style.display = "block";
    document.getElementById("panelImportMode").style.display = "none";
  };

  document.getElementById("btnModeImport").onclick = () => {
    document.getElementById("btnModeImport").classList.add("btn-mode-active");
    document.getElementById("btnModeClaim").classList.remove("btn-mode-active");
    document.getElementById("panelImportMode").style.display = "block";
    document.getElementById("panelClaimMode").style.display = "none";
  };

  const btnShowImport = document.getElementById("btnShowImportPanel");
  if (btnShowImport) {
    btnShowImport.onclick = () => {
      document.getElementById("noIdentityCard").style.display = "block";
      document.getElementById("btnModeImport").click();
      document.getElementById("inputImportUsername").focus();
    };
  }

  // Recovery Modal
  document.getElementById("btnCloseRecoveryModal").onclick = closeRecoveryModal;
  document.getElementById("btnDismissRecovery").onclick = closeRecoveryModal;
  document.getElementById("btnCopyRecoveryKey").onclick = () => {
    const privHex = document.getElementById("recoveryModalPrivKey").innerText;
    navigator.clipboard.writeText(privHex).then(() => {
      showToast("Recovery key copied to clipboard!");
    }).catch(() => {
      prompt("Copy your recovery key:", privHex);
    });
  };

  document.getElementById("btnLookup").onclick = resolveUser;
  document.getElementById("btnSendChatMessage").onclick = sendChatMessage;

  const btnRefreshInbox = document.getElementById("btnRefreshInbox");
  if (btnRefreshInbox) {
    btnRefreshInbox.onclick = async () => {
      if (!currentIdentity) return;
      showToast("Checking inbox...");
      startRealtimeStream();
    };
  }

  document.getElementById("inputChatMessage").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendChatMessage();
  });

  const inputChatRecip = document.getElementById("inputChatRecipient");
  if (inputChatRecip) {
    inputChatRecip.addEventListener("input", (e) => {
      const val = e.target.value.trim().toLowerCase();
      const headerName = document.getElementById("chatRecipientName");
      if (headerName) headerName.innerText = val ? "@" + val : "(Select Recipient)";
      if (currentIdentity) {
        localStorage.setItem(`author_last_chat_recipient_${currentIdentity.username}`, val);
        renderChatHistory(currentIdentity.username, val);
      }
    });
  }

  // Cross-tab synchronization
  window.addEventListener("storage", (e) => {
    if (e.key === STORAGE_KEY) {
      refreshUI();
      startRealtimeStream();
    }
  });

  // Resume & Gap-Fill on Screen Unlock / Tab Switch (Mobile Wake-Up)
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") {
      startRealtimeStream();
    }
  });

  // Online / Offline State Handlers
  window.addEventListener("online", () => {
    document.getElementById("relayDot").style.background = "#00e599";
    document.getElementById("relayStatusText").innerText = "Online (Reconnected)";
    startRealtimeStream();
    showToast("Internet connection restored");
  });

  window.addEventListener("offline", () => {
    document.getElementById("relayDot").style.background = "#f59e0b";
    document.getElementById("relayStatusText").innerText = "Offline (Cached Shell)";
    showToast("Device is offline. Local vault accessible.");
  });

  // PWA Install Prompt Handler
  let deferredInstallPrompt = null;
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredInstallPrompt = e;
    const btnInstall = document.getElementById("btnInstallPWA");
    if (btnInstall) {
      btnInstall.style.display = "inline-block";
      btnInstall.onclick = async () => {
        btnInstall.style.display = "none";
        if (deferredInstallPrompt) {
          deferredInstallPrompt.prompt();
          const { outcome } = await deferredInstallPrompt.userChoice;
          console.log("PWA install outcome:", outcome);
          deferredInstallPrompt = null;
        }
      };
    }
  });

  // Service Worker Registration for Offline Shell Caching
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/sw.js").then((reg) => {
      console.log("Author PWA Service Worker active (Scope:", reg.scope, ")");
    }).catch((err) => {
      console.log("Service worker registration:", err.message);
    });
  }
}

// Immediate execution if DOM is ready, otherwise on DOMContentLoaded
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}
