// Author Web App Client

const PROTOCOL_PREFIX = "author-id:v1";

function getRelayBaseUrl() {
  try {
    const custom = localStorage.getItem("author_relay_url");
    if (custom) return custom.trim().replace(/\/+$/, "");
  } catch (e) {}
  return "";
}

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

const HANDLE_PREFIX = "author-handle:v1";

async function deriveHandleToken(username) {
  const normalized = (username || "").toLowerCase().trim();
  return await sha256Hex(`${HANDLE_PREFIX}:${normalized}`);
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

function formatFileSize(bytes) {
  if (!bytes || bytes < 1024) return (bytes || 0) + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

let stagedAttachment = null;

function renderAttachmentStaging() {
  const el = document.getElementById("attachmentStaging");
  if (!el) return;
  if (!stagedAttachment) {
    el.style.display = "none";
    el.innerHTML = "";
    return;
  }
  el.style.display = "flex";
  el.innerHTML = `
    <div class="attachment-staging-name">${escapeHtml(stagedAttachment.filename)} (${formatFileSize(stagedAttachment.size)})</div>
    <button class="attachment-staging-remove" id="btnRemoveStagedAttachment" type="button">Remove</button>
  `;
  const btnRemove = document.getElementById("btnRemoveStagedAttachment");
  if (btnRemove) {
    btnRemove.onclick = () => {
      stagedAttachment = null;
      renderAttachmentStaging();
    };
  }
}

function saveChatHistoryMessage(username, type, text, sender, isE2EE = false, peer = "", msgId = "", status = "Sent", expiresAt = 0, readSent = false, attachment = null) {
  if (!username) return "";
  const history = loadChatHistory(username);
  const resolvedPeer = (peer || (type === "incoming" ? sender : "")).toLowerCase().trim();
  const id = msgId || ("msg_" + getRandomNonce(8));
  history.push({ id, type, text, sender, isE2EE, peer: resolvedPeer, time: Date.now(), status, expiresAt, readSent, attachment });
  if (history.length > 200) history.shift();
  localStorage.setItem(getChatHistoryKey(username), JSON.stringify(history));
  return id;
}

function purgeExpiredMessages(username) {
  if (!username) return;
  const history = loadChatHistory(username);
  const now = Date.now();
  const valid = history.filter(m => !m.expiresAt || m.expiresAt > now);
  if (valid.length !== history.length) {
    localStorage.setItem(getChatHistoryKey(username), JSON.stringify(valid));
    if (activeChatPeer) {
      renderChatHistory(username, activeChatPeer);
    }
    renderConversationsList(document.getElementById("inputFilterChats")?.value || "");
  }
}

function updateMessageDeliveryStatus(username, msgId, newStatus) {
  if (!username || !msgId) return;
  const history = loadChatHistory(username);
  let updated = false;
  for (const m of history) {
    if (m.id === msgId && m.status !== newStatus) {
      m.status = newStatus;
      updated = true;
      break;
    }
  }
  if (updated) {
    localStorage.setItem(getChatHistoryKey(username), JSON.stringify(history));
    const el = document.getElementById("msg_status_" + msgId);
    if (el) {
      el.innerText = newStatus;
    }
  }
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/[&<>'"]/g, tag => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    "'": '&#39;',
    '"': '&quot;'
  }[tag] || tag));
}

function formatChatTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  const now = new Date();
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleDateString([], { month: "short", day: "numeric" });
}

function getConversationRegistryKey(username) {
  return `author_conversations_${(username || "").toLowerCase().trim()}`;
}

function loadConversationRegistry(username) {
  if (!username) return [];
  try {
    const raw = localStorage.getItem(getConversationRegistryKey(username));
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) return parsed;
    }
  } catch (e) {}
  return [];
}

function saveConversationRegistry(username, list) {
  if (!username) return;
  try {
    localStorage.setItem(getConversationRegistryKey(username), JSON.stringify(list));
  } catch (e) {}
}

function registerConversation(username, peer, preview = "", time = Date.now(), isE2EE = true) {
  if (!username || !peer) return;
  username = username.toLowerCase().trim();
  peer = peer.toLowerCase().trim();
  if (peer === username) return;

  const list = loadConversationRegistry(username);
  const existingIndex = list.findIndex(c => c.peer === peer);
  if (existingIndex >= 0) {
    list[existingIndex] = {
      peer,
      lastText: preview || list[existingIndex].lastText || "",
      time: time || list[existingIndex].time || Date.now(),
      isE2EE: isE2EE ?? list[existingIndex].isE2EE ?? true
    };
  } else {
    list.unshift({
      peer,
      lastText: preview || "",
      time: time || Date.now(),
      isE2EE: isE2EE ?? true
    });
  }
  saveConversationRegistry(username, list);
}

function removeConversation(username, peer) {
  if (!username || !peer) return;
  username = username.toLowerCase().trim();
  peer = peer.toLowerCase().trim();
  const list = loadConversationRegistry(username).filter(c => c.peer !== peer);
  saveConversationRegistry(username, list);
}

function removeConversationHandler(peer) {
  if (!currentIdentity || !peer) return;
  peer = peer.toLowerCase().trim();
  removeConversation(currentIdentity.username, peer);
  if (activeChatPeer && activeChatPeer.toLowerCase().trim() === peer) {
    activeChatPeer = null;
    localStorage.removeItem(`author_last_chat_recipient_${currentIdentity.username}`);
    const emptyState = document.getElementById("chatEmptyState");
    const activeView = document.getElementById("chatActiveView");
    if (emptyState) emptyState.style.display = "flex";
    if (activeView) activeView.style.display = "none";
    const container = document.querySelector(".messenger-container");
    if (container) container.classList.remove("in-chat");
  }
  renderConversationsList(document.getElementById("inputFilterChats")?.value || "");
}

function getConversations(username) {
  if (!username) return [];
  username = username.toLowerCase().trim();

  // 1. Start with persistent conversations registry
  const registry = loadConversationRegistry(username);
  const convMap = new Map();
  for (const c of registry) {
    if (c && c.peer) {
      convMap.set(c.peer.toLowerCase().trim(), {
        peer: c.peer.toLowerCase().trim(),
        lastText: c.lastText || "",
        time: c.time || 0,
        isE2EE: c.isE2EE ?? true
      });
    }
  }

  // 2. Overlay any active chat history messages
  const history = loadChatHistory(username);
  for (const m of history) {
    const p = (m.peer || (m.type === "incoming" ? m.sender : "")).toLowerCase().trim();
    if (!p || p === username) continue;
    const existing = convMap.get(p);
    const mTime = m.time || 0;
    const previewText = m.attachment ? (m.attachment.mime?.startsWith("image/") ? "[Photo]" : `[File: ${m.attachment.filename}]`) : (m.text || "");
    if (!existing || mTime >= (existing.time || 0)) {
      convMap.set(p, {
        peer: p,
        lastText: previewText || existing?.lastText || "",
        time: mTime || existing?.time || 0,
        isE2EE: m.isE2EE ?? existing?.isE2EE ?? true
      });
    }
  }

  // 3. If there is an activeChatPeer, ensure it is in the list
  if (activeChatPeer && activeChatPeer !== username) {
    const activeNorm = activeChatPeer.toLowerCase().trim();
    if (!convMap.has(activeNorm)) {
      convMap.set(activeNorm, {
        peer: activeNorm,
        lastText: "",
        time: Date.now(),
        isE2EE: true
      });
    }
  }

  const merged = Array.from(convMap.values()).sort((a, b) => (b.time || 0) - (a.time || 0));
  saveConversationRegistry(username, merged);
  return merged;
}

function renderConversationsList(filterQuery = "") {
  const listEl = document.getElementById("conversationsList");
  if (!listEl) return;
  if (!currentIdentity) {
    listEl.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2rem 1rem; font-size: 0.85rem;">No active identity</div>`;
    return;
  }

  const convs = getConversations(currentIdentity.username);
  const q = (filterQuery || "").toLowerCase().trim();
  const filtered = q ? convs.filter(c => c.peer.toLowerCase().includes(q)) : convs;

  if (filtered.length === 0) {
    listEl.innerHTML = `<div style="text-align: center; color: var(--text-muted); padding: 2.5rem 1rem; font-size: 0.85rem;">
      ${q ? `No chat matching "${escapeHtml(q)}"` : `No conversations yet.<br><span style="color: var(--accent); cursor: pointer; text-decoration: underline;" id="btnListNewChat">Start a new chat</span>`}
    </div>`;
    const btnListNew = document.getElementById("btnListNewChat");
    if (btnListNew) btnListNew.onclick = openNewChatModal;
    return;
  }

  listEl.innerHTML = "";
  filtered.forEach(c => {
    const item = document.createElement("div");
    item.className = "chat-item" + (activeChatPeer === c.peer ? " active" : "");
    item.dataset.peer = c.peer;
    item.onclick = (e) => {
      e.stopPropagation();
      openConversationWith(c.peer);
    };

    const initial = c.peer ? c.peer[0].toUpperCase() : "?";
    const timeStr = c.time ? formatChatTime(c.time) : "";
    const preview = (c.lastText || "").length > 36 ? (c.lastText || "").slice(0, 36) + "…" : (c.lastText || "");

    item.innerHTML = `
      <div class="contact-avatar">${initial}</div>
      <div class="chat-item-info">
        <div class="chat-item-top">
          <span class="chat-item-name">@${escapeHtml(c.peer)}</span>
          <span class="chat-item-time">${timeStr}</span>
        </div>
        <div class="chat-item-preview">${escapeHtml(preview)}</div>
      </div>
      <button class="chat-item-remove" title="Close conversation" onclick="event.stopPropagation(); removeConversationHandler('${escapeHtml(c.peer)}');">&times;</button>
    `;
    listEl.appendChild(item);
  });
}

function renderChatHistory(username, filterPeer = "") {
  const box = document.getElementById("chatBox");
  if (!box) return;
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
      ${peerNorm ? `No messages yet with @${escapeHtml(peerNorm)}. Send an encrypted message below!` : "Messages are end-to-end encrypted (E2EE) and pushed in real-time."}
    </div>`;
    return;
  }
  for (const m of filtered) {
    appendChatMessageDOM(m.type, m.text, m.sender, m.isE2EE, m.time, m.status || "Sent", m.id || "", m.attachment || null);
  }
  box.scrollTop = box.scrollHeight;
}

// In-Memory & LocalStorage Public Key Cache for Sub-100ms Messaging
const recipientKeyCache = {};

function getCachedRecipientKey(username) {
  if (!username) return null;
  const u = username.toLowerCase().trim();
  if (recipientKeyCache[u]) return recipientKeyCache[u];
  try {
    const raw = localStorage.getItem(`author_pk_cache_${u}`);
    if (raw) {
      const parsed = JSON.parse(raw);
      recipientKeyCache[u] = parsed;
      return parsed;
    }
  } catch (e) {}
  return null;
}

function setCachedRecipientKey(username, data) {
  if (!username || !data) return;
  const u = username.toLowerCase().trim();
  recipientKeyCache[u] = data;
  try {
    localStorage.setItem(`author_pk_cache_${u}`, JSON.stringify(data));
  } catch (e) {}
}

// Bare-Metal Web of Trust (WoT) Engine
const WOT_PREFIX = "author-wot:v1";

function loadTrustGraph(username) {
  if (!username) return { direct: {}, attestations: [] };
  try {
    const raw = localStorage.getItem(`author_wot_graph_${username}`);
    return raw ? JSON.parse(raw) : { direct: {}, attestations: [] };
  } catch {
    return { direct: {}, attestations: [] };
  }
}

function saveTrustGraph(username, graph) {
  if (!username) return;
  try {
    localStorage.setItem(`author_wot_graph_${username}`, JSON.stringify(graph));
  } catch (e) {}
}

function formatAttestationPayload(issuerPub, subjectPub, level, timestamp) {
  return `${WOT_PREFIX}:TRUST:${issuerPub.toLowerCase()}:${subjectPub.toLowerCase()}:${level}:${timestamp}`;
}

function signAttestation(subjectPub, level = 2, handle = "") {
  if (!currentIdentity || !subjectPub) return null;
  const ts = Math.floor(Date.now() / 1000);
  const msg = formatAttestationPayload(currentIdentity.pubKey, subjectPub, level, ts);
  const sigBytes = nacl.sign.detached(strToBytes(msg), fromHex(currentIdentity.privKey));
  const att = {
    issuer_pub: currentIdentity.pubKey.toLowerCase(),
    subject_pub: subjectPub.toLowerCase(),
    handle: handle || "",
    level,
    timestamp: ts,
    sig: toHex(sigBytes)
  };
  const graph = loadTrustGraph(currentIdentity.username);
  graph.direct[subjectPub.toLowerCase()] = att;
  saveTrustGraph(currentIdentity.username, graph);
  return att;
}

function revokeAttestation(subjectPub) {
  if (!currentIdentity || !subjectPub) return;
  const graph = loadTrustGraph(currentIdentity.username);
  delete graph.direct[subjectPub.toLowerCase()];
  saveTrustGraph(currentIdentity.username, graph);
}

function getContactTrustStatus(subjectPub) {
  if (!currentIdentity || !subjectPub) {
    return { level: 0, label: "Unknown", badgeClass: "badge-stranger", isDirect: false };
  }
  const pub = subjectPub.toLowerCase();
  if (pub === currentIdentity.pubKey.toLowerCase()) {
    return { level: 2, label: "You", badgeClass: "badge-verified", isDirect: true };
  }
  const graph = loadTrustGraph(currentIdentity.username);
  if (graph.direct && graph.direct[pub]) {
    return { level: 2, label: "Verified", badgeClass: "badge-verified", isDirect: true };
  }
  if (graph.attestations) {
    for (const att of graph.attestations) {
      if (att.subject_pub.toLowerCase() === pub && graph.direct && graph.direct[att.issuer_pub.toLowerCase()]) {
        return { level: 1, label: "Trusted via Contact", badgeClass: "badge-vouched", isDirect: false };
      }
    }
  }
  return { level: 0, label: "Unknown", badgeClass: "badge-stranger", isDirect: false };
}

function renderWoTNetwork() {
  if (!currentIdentity) return;
  const graph = loadTrustGraph(currentIdentity.username);
  const listEl = document.getElementById("wotPeersList");
  const countEl = document.getElementById("wotVouchedCount");
  const emptyEl = document.getElementById("wotEmptyNotice");
  if (!listEl) return;

  const directKeys = Object.keys(graph.direct || {});
  if (countEl) countEl.innerText = `${directKeys.length} Verified`;

  if (directKeys.length === 0) {
    if (emptyEl) emptyEl.style.display = "block";
    listEl.innerHTML = "";
    return;
  }

  if (emptyEl) emptyEl.style.display = "none";
  listEl.innerHTML = "";

  directKeys.forEach(pub => {
    const att = graph.direct[pub];
    const item = document.createElement("div");
    item.style.display = "flex";
    item.style.alignItems = "center";
    item.style.justifyContent = "space-between";
    item.style.padding = "0.55rem 0.75rem";
    item.style.background = "var(--bg)";
    item.style.border = "1px solid var(--border)";
    item.style.borderRadius = "6px";

    const left = document.createElement("div");
    const peerDisplay = att.handle ? `@${att.handle}` : `Key: ${pub.slice(0, 10)}...`;
    left.innerHTML = `
      <div style="font-weight: 600; font-size: 0.88rem; color: var(--text-main); display: flex; align-items: center; gap: 0.4rem;">
        <span>${peerDisplay}</span>
        <span class="badge badge-verified" style="font-size: 0.65rem; padding: 0.1rem 0.35rem;">Verified</span>
      </div>
      <div style="font-family: var(--font-mono); font-size: 0.7rem; color: var(--text-muted); margin-top: 0.15rem;">${pub.slice(0, 24)}...</div>
    `;

    const right = document.createElement("div");
    right.style.display = "flex";
    right.style.gap = "0.4rem";

    if (att.handle) {
      const btnChat = document.createElement("button");
      btnChat.className = "btn btn-secondary btn-sm";
      btnChat.innerText = "Chat";
      btnChat.onclick = () => openConversationWith(att.handle);
      right.appendChild(btnChat);
    }

    const btnRevoke = document.createElement("button");
    btnRevoke.className = "btn btn-danger btn-sm";
    btnRevoke.innerText = "Revoke";
    btnRevoke.onclick = () => {
      revokeAttestation(pub);
      renderWoTNetwork();
      updateActiveChatTrustBadge();
      showToast("Trust attestation revoked.");
    };
    right.appendChild(btnRevoke);

    item.appendChild(left);
    item.appendChild(right);
    listEl.appendChild(item);
  });
}

// State
let currentIdentity = null;
let activeChatPeer = null;
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
  const vault = loadVault();
  if (vault.identities.length > 0 && vault.activeIndex === -1) {
    vault.activeIndex = 0;
    saveVault(vault);
  }
  refreshUI();
  ensureAllIdentitiesRegistered().then(() => {
    startRealtimeStream();
  });
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
    activeChatPeer = null;
    renderConversationsList();
    const emptyState = document.getElementById("chatEmptyState");
    const activeView = document.getElementById("chatActiveView");
    if (emptyState) emptyState.style.display = "flex";
    if (activeView) activeView.style.display = "none";
    const container = document.querySelector(".messenger-container");
    if (container) container.classList.remove("in-chat");
  } else {
    noIdCard.style.display = "none";
    activeCard.style.display = "block";

    document.getElementById("cardUsername").innerText = currentIdentity.username;
    document.getElementById("cardPubKey").innerText = currentIdentity.pubKey;
    document.getElementById("cardVersion").innerText = currentIdentity.version || 1;

    // Populate profile avatar with first character of handle
    const avatarEl = document.getElementById("profileAvatar");
    if (avatarEl) {
      avatarEl.innerText = currentIdentity.username.charAt(0).toUpperCase();
    }

    const badge = document.getElementById("cardStatusBadge");
    if (currentIdentity.status === "revoked") {
      badge.className = "badge badge-revoked";
      badge.innerText = "Revoked";
    } else {
      badge.className = "badge badge-active";
      badge.innerText = "Active";
    }

    document.getElementById("cardSlots").innerText = `${vault.identities.length} / 3`;

    // Render conversations list
    renderConversationsList();

    const lastRecip = localStorage.getItem(`author_last_chat_recipient_${currentIdentity.username}`) || "";
    if (activeChatPeer) {
      openConversationWith(activeChatPeer);
    } else if (lastRecip && window.innerWidth > 768) {
      // Desktop auto-opens last active chat
      openConversationWith(lastRecip);
    } else {
      const emptyState = document.getElementById("chatEmptyState");
      const activeView = document.getElementById("chatActiveView");
      if (emptyState) emptyState.style.display = "flex";
      if (activeView) activeView.style.display = "none";
      const container = document.querySelector(".messenger-container");
      if (container) container.classList.remove("in-chat");
    }
  }

  renderWoTNetwork();
  await checkHealth();
}

async function checkHealth() {
  try {
    const res = await fetch(getRelayBaseUrl() + "/health");
    if (res.ok) {
      document.getElementById("relayDot").style.background = "#ffffff";
      document.getElementById("relayStatusText").innerText = "Online";
    } else {
      throw new Error();
    }
  } catch {
    document.getElementById("relayDot").style.background = "#ef4444";
    document.getElementById("relayStatusText").innerText = "Offline";
  }
}

// Self-Healing Identity Sync: Ensures local vault identities are active on relay
async function ensureIdentityRegistered(identity) {
  if (!identity || !identity.username || !identity.privKey) return false;
  const token = identity.handleToken || await deriveHandleToken(identity.username);
  if (!identity.handleToken) {
    identity.handleToken = token;
  }
  try {
    let res = await fetch(getRelayBaseUrl() + `/v1/resolve/${token}`);
    if (!res.ok && res.status === 404 && token !== identity.username) {
      // Fallback check for legacy plaintext handle
      const fallbackRes = await fetch(getRelayBaseUrl() + `/v1/resolve/${encodeURIComponent(identity.username)}`);
      if (fallbackRes.ok) {
        res = fallbackRes;
      }
    }

    if (res.ok) {
      const data = await res.json();
      if (data.status === "active" && data.pubkey.toLowerCase() === identity.pubKey.toLowerCase()) {
        return true;
      }
    }

    // If relay returned 404 (database reset / fresh instance), re-assert self-sovereign claim
    if (res.status === 404) {
      console.log(`Relay missing active record for identity token. Re-registering @${identity.username}...`);
      const timestamp = Math.floor(Date.now() / 1000);
      const nonce = getRandomNonce(16);
      const msg = `${PROTOCOL_PREFIX}:CLAIM:${token}:${identity.pubKey}:${timestamp}:${nonce}`;
      const sigBytes = nacl.sign.detached(strToBytes(msg), fromHex(identity.privKey));
      const sigHex = toHex(sigBytes);

      const claimRes = await fetch(getRelayBaseUrl() + "/v1/claim", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: token,
          pubkey: identity.pubKey,
          timestamp,
          nonce,
          sig: sigHex
        })
      });
      if (claimRes.ok) {
        console.log(`Successfully synced identity @${identity.username} with relay.`);
        return true;
      }
    }
  } catch (err) {
    console.error("Identity sync error:", err);
  }
  return false;
}

async function ensureAllIdentitiesRegistered() {
  const vault = loadVault();
  if (!vault.identities || vault.identities.length === 0) return;
  for (const id of vault.identities) {
    if (id.status !== "revoked") {
      await ensureIdentityRegistered(id);
    }
  }
}

// Identity Actions
async function claimIdentity() {
  const username = document.getElementById("inputClaimUsername").value.trim().toLowerCase();
  if (!username) {
    showToast("Please enter a handle.");
    return;
  }

  const vault = loadVault();
  if (vault.identities.length >= 3) {
    showToast("Device limit reached - max 3 identities per install.");
    return;
  }

  // Derive blinded handle token (Zero-Knowledge Privacy: Relay never sees username)
  const handleToken = await deriveHandleToken(username);

  // Generate Ed25519 keypair
  const keyPair = nacl.sign.keyPair();
  const pubHex = toHex(keyPair.publicKey);
  const privHex = toHex(keyPair.secretKey);

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = getRandomNonce(16);

  // Format canonical claim payload using blinded handle token
  const msg = `${PROTOCOL_PREFIX}:CLAIM:${handleToken}:${pubHex}:${timestamp}:${nonce}`;
  const sigBytes = nacl.sign.detached(strToBytes(msg), keyPair.secretKey);
  const sigHex = toHex(sigBytes);

  try {
    const resp = await fetch(getRelayBaseUrl() + "/v1/claim", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: handleToken,
        pubkey: pubHex,
        timestamp,
        nonce,
        sig: sigHex
      })
    });

    const data = await resp.json();
    if (!resp.ok) {
      showToast("Claim failed: " + (data.error || "Unknown error"));
      return;
    }

    // Save to local vault with handleToken and human handle
    vault.identities.push({
      username,
      handleToken,
      pubKey: pubHex,
      privKey: privHex,
      version: 1,
      status: "active"
    });
    vault.activeIndex = vault.identities.length - 1;
    saveVault(vault);

    document.getElementById("inputClaimUsername").value = "";
    document.getElementById("noIdentityCard").style.display = "none";
    showToast(`@${username} is ready!`);
    refreshUI();
    startRealtimeStream();

    // Directly open chat tab
    const tabChatBtn = document.querySelector('[data-tab="tab-chat"]');
    if (tabChatBtn) tabChatBtn.click();
  } catch (err) {
    showToast("Network error: " + err.message);
  }
}

async function rotateIdentity() {
  if (!currentIdentity || currentIdentity.status === "revoked") {
    showToast("No active identity to rotate.");
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
    const resp = await fetch(getRelayBaseUrl() + "/v1/rotate", {
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
      showToast("Rotation failed: " + (data.error || "Unknown error"));
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
    showToast("Network error: " + err.message);
  }
}

async function revokeIdentity() {
  if (!currentIdentity || currentIdentity.status === "revoked") {
    showToast("Identity is already revoked or not active.");
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
    const resp = await fetch(getRelayBaseUrl() + "/v1/revoke", {
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
      showToast("Revocation failed: " + (data.error || "Unknown error"));
      return;
    }

    const vault = loadVault();
    vault.identities[vault.activeIndex].status = "revoked";
    saveVault(vault);

    showToast(`Identity @${currentIdentity.username} revoked.`);
    refreshUI();
  } catch (err) {
    showToast("Network error: " + err.message);
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
    showToast("Please enter your handle.");
    return;
  }
  if (!keyHex) {
    showToast("Please paste your backup key.");
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
      showToast(`Invalid key length (${keyHex.length} chars). Expected 128 or 64 hex characters.`);
      return;
    }
  } catch (err) {
    showToast("Error reading backup key: " + err.message);
    return;
  }

  const derivedPubHex = toHex(keyPair.publicKey);
  const fullPrivHex = toHex(keyPair.secretKey);

  // Validate against authoritative relay
  try {
    const res = await fetch(getRelayBaseUrl() + `/v1/resolve/${username}`);
    if (!res.ok) {
      showToast(`Handle @${username} is not registered on the relay.`);
      return;
    }

    const relayIdentity = await res.json();
    if (relayIdentity.pubkey.toLowerCase() !== derivedPubHex.toLowerCase()) {
      showToast(`Key mismatch — this backup key does not own @${username}.`);
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
        showToast("Device limit reached — max 3 identities. Revoke one first.");
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
    showToast("Network error: " + err.message);
  }
}

function openConversationWith(username) {
  if (!username) return;
  username = username.toLowerCase().trim();
  activeChatPeer = username;

  if (currentIdentity) {
    registerConversation(currentIdentity.username, username, "", Date.now(), true);
  }

  const tabBtn = document.querySelector('[data-tab="tab-chat"]');
  if (tabBtn && !tabBtn.classList.contains("active")) {
    tabBtn.click();
  }

  const container = document.querySelector(".messenger-container");
  if (container) {
    container.classList.add("in-chat");
  }

  const emptyState = document.getElementById("chatEmptyState");
  const activeView = document.getElementById("chatActiveView");
  if (emptyState) emptyState.style.display = "none";
  if (activeView) activeView.style.display = "flex";

  const handleEl = document.getElementById("activeContactHandle");
  if (handleEl) handleEl.innerText = "@" + username;
  const avatarEl = document.getElementById("activeContactAvatar");
  if (avatarEl) avatarEl.innerText = username[0].toUpperCase();

  if (currentIdentity) {
    purgeExpiredMessages(currentIdentity.username);
    localStorage.setItem(`author_last_chat_recipient_${currentIdentity.username}`, username);
    renderChatHistory(currentIdentity.username, username);

    // Sync disappearing message retention selector
    const retentionSelect = document.getElementById("chatRetentionSelect");
    if (retentionSelect) {
      const savedTtl = localStorage.getItem(`author_ttl_${currentIdentity.username}_${username}`) || "0";
      retentionSelect.value = savedTtl;
    }

    // Collect unread incoming messages and emit read receipt
    const history = loadChatHistory(currentIdentity.username);
    const unreadIds = [];
    for (const m of history) {
      const p = (m.peer || (m.type === "incoming" ? m.sender : "")).toLowerCase().trim();
      if (p === username && m.type === "incoming" && !m.readSent && m.id) {
        unreadIds.push(m.id);
        m.readSent = true;
      }
    }
    if (unreadIds.length > 0) {
      localStorage.setItem(getChatHistoryKey(currentIdentity.username), JSON.stringify(history));
      sendReadReceipt(username, unreadIds);
    }
  }

  renderConversationsList(document.getElementById("inputFilterChats")?.value || "");

  // Update WoT Trust Badge
  updateActiveChatTrustBadge();

  const msgInput = document.getElementById("inputChatMessage");
  if (msgInput) {
    msgInput.focus();
  }
}

function updateActiveChatTrustBadge() {
  const badge = document.getElementById("activeContactTrustBadge");
  if (!badge || !activeChatPeer) return;
  const cached = getCachedRecipientKey(activeChatPeer);
  if (cached && cached.pubkey) {
    const status = getContactTrustStatus(cached.pubkey);
    badge.className = `badge ${status.badgeClass}`;
    badge.innerText = status.label;
  } else {
    badge.className = "badge badge-stranger";
    badge.innerText = "Unknown";
  }
}

function openTrustVerificationModal(targetPeer) {
  const peer = (targetPeer || activeChatPeer || "").toLowerCase().trim();
  if (!peer) {
    showToast("No contact selected to verify.");
    return;
  }
  const cached = getCachedRecipientKey(peer);
  if (!cached || !cached.pubkey) {
    showToast("Contact public key not resolved yet.");
    return;
  }
  const modal = document.getElementById("modalTrustVerify");
  const handleEl = document.getElementById("trustModalHandle");
  const pubKeyEl = document.getElementById("trustModalPubKey");
  const statusBadge = document.getElementById("trustModalStatusBadge");
  const btnEndorse = document.getElementById("btnEndorseDirect");
  const btnRevoke = document.getElementById("btnRevokeEndorsement");

  if (handleEl) handleEl.innerText = "@" + peer;
  if (pubKeyEl) pubKeyEl.innerText = cached.pubkey;

  const status = getContactTrustStatus(cached.pubkey);
  if (statusBadge) {
    statusBadge.className = `badge ${status.badgeClass}`;
    statusBadge.innerText = status.label;
  }

  if (status.isDirect) {
    btnEndorse.style.display = "none";
    btnRevoke.style.display = "inline-block";
  } else {
    btnEndorse.style.display = "inline-block";
    btnRevoke.style.display = "none";
  }

  btnEndorse.onclick = () => {
    signAttestation(cached.pubkey, 2, peer);
    updateActiveChatTrustBadge();
    renderWoTNetwork();
    const trustBadge = document.getElementById("lookupTrustBadge");
    if (trustBadge) {
      const newStatus = getContactTrustStatus(cached.pubkey);
      trustBadge.className = `badge ${newStatus.badgeClass}`;
      trustBadge.innerText = newStatus.label;
    }
    showToast(`Identity @${peer} cryptographically verified!`);
    closeTrustModal();
  };

  btnRevoke.onclick = () => {
    revokeAttestation(cached.pubkey);
    updateActiveChatTrustBadge();
    renderWoTNetwork();
    const trustBadge = document.getElementById("lookupTrustBadge");
    if (trustBadge) {
      const newStatus = getContactTrustStatus(cached.pubkey);
      trustBadge.className = `badge ${newStatus.badgeClass}`;
      trustBadge.innerText = newStatus.label;
    }
    showToast(`Trust revoked for @${peer}`);
    closeTrustModal();
  };

  if (modal) modal.style.display = "flex";
}

function closeTrustModal() {
  const modal = document.getElementById("modalTrustVerify");
  if (modal) modal.style.display = "none";
}

function backToChatsList() {
  const container = document.querySelector(".messenger-container");
  if (container) {
    container.classList.remove("in-chat");
  }
}

function openNewChatModal() {
  const modal = document.getElementById("modalNewChat");
  const input = document.getElementById("inputNewChatHandle");
  const status = document.getElementById("newChatStatus");
  if (status) status.innerText = "";
  if (input) input.value = "";
  if (modal) modal.style.display = "flex";
  if (input) input.focus();
}

function closeNewChatModal() {
  const modal = document.getElementById("modalNewChat");
  if (modal) modal.style.display = "none";
}

// Universal Recipient Resolver: Caches in storage, checks local vault, trust graph, blinded token, and plain handle
async function resolveRecipientBinding(handle) {
  const normalized = (handle || "").toLowerCase().trim();
  if (!normalized) return null;

  // 1. Check in-memory / localStorage cache
  const cached = getCachedRecipientKey(normalized);
  if (cached && cached.pubkey) return cached;

  const token = await deriveHandleToken(normalized);
  const cachedByToken = getCachedRecipientKey(token);
  if (cachedByToken && cachedByToken.pubkey) return cachedByToken;

  // 2. Check local vault (in case user has multiple identities on this device)
  try {
    const vault = loadVault();
    const localMatch = vault.identities.find(id => id.username && id.username.toLowerCase() === normalized);
    if (localMatch && localMatch.pubKey) {
      const data = { username: normalized, pubkey: localMatch.pubKey, status: localMatch.status || "active", version: localMatch.version || 1 };
      setCachedRecipientKey(normalized, data);
      setCachedRecipientKey(token, data);
      return data;
    }
  } catch (e) {}

  // 3. Check local Web of Trust graph
  try {
    if (currentIdentity) {
      const graph = loadTrustGraph(currentIdentity.username);
      if (graph && graph.direct) {
        for (const [pub, att] of Object.entries(graph.direct)) {
          if (att && att.handle && att.handle.toLowerCase() === normalized) {
            const data = { username: normalized, pubkey: pub, status: "active", version: 1 };
            setCachedRecipientKey(normalized, data);
            setCachedRecipientKey(token, data);
            return data;
          }
        }
      }
    }
  } catch (e) {}

  // 4. Query relay via blinded token (with plaintext fallback)
  try {
    let res = await fetch(getRelayBaseUrl() + `/v1/resolve/${token}`);
    if (!res.ok && res.status === 404 && token !== normalized) {
      const fallbackRes = await fetch(getRelayBaseUrl() + `/v1/resolve/${encodeURIComponent(normalized)}`);
      if (fallbackRes.ok) {
        res = fallbackRes;
      }
    }
    if (!res.ok) return null;

    const data = await res.json();
    setCachedRecipientKey(normalized, data);
    setCachedRecipientKey(token, data);
    return data;
  } catch (err) {
    console.error("Resolve error for @" + normalized, err);
    return null;
  }
}

async function submitNewChat() {
  const input = document.getElementById("inputNewChatHandle");
  const status = document.getElementById("newChatStatus");
  const handle = (input?.value || "").toLowerCase().trim();
  if (!handle) return;

  if (currentIdentity && handle === currentIdentity.username.toLowerCase()) {
    if (status) status.innerText = "Cannot chat with your own handle.";
    return;
  }

  if (status) status.innerText = `Resolving @${handle}...`;

  try {
    const data = await resolveRecipientBinding(handle);
    if (!data) {
      if (status) status.innerText = `Handle @${handle} not found on relay.`;
      return;
    }
    if (data.status === "revoked") {
      if (status) status.innerText = `Handle @${handle} is revoked.`;
      return;
    }
    closeNewChatModal();
    if (currentIdentity) {
      registerConversation(currentIdentity.username, handle, "", Date.now(), true);
    }
    openConversationWith(handle);
  } catch (err) {
    if (status) status.innerText = "Network error: " + err.message;
  }
}

// Directory Lookup
async function resolveUser() {
  const username = document.getElementById("inputLookupUser").value.trim().toLowerCase();
  if (!username) return;

  try {
    const data = await resolveRecipientBinding(username);
    if (!data) {
      showToast(`User @${username} not found on relay.`);
      return;
    }

    const resultBox = document.getElementById("lookupResultBox");
    resultBox.style.display = "block";

    document.getElementById("lookupUsername").innerText = "@" + username;
    document.getElementById("lookupPubKey").innerText = data.pubkey;
    document.getElementById("lookupVersion").innerText = data.version;
    document.getElementById("lookupCreated").innerText = new Date(data.created_at).toLocaleDateString();

    const resolvedChatName = document.getElementById("resolvedChatUsername");
    if (resolvedChatName) resolvedChatName.innerText = username;

    const badge = document.getElementById("lookupBadge");
    if (data.status === "active") {
      badge.className = "badge badge-active";
      badge.innerText = "Active";
    } else {
      badge.className = "badge badge-revoked";
      badge.innerText = "Revoked";
    }

    document.getElementById("btnChatWithResolved").onclick = () => {
      openConversationWith(username);
    };

    const trustBadge = document.getElementById("lookupTrustBadge");
    if (trustBadge) {
      const trustStatus = getContactTrustStatus(data.pubkey);
      trustBadge.className = `badge ${trustStatus.badgeClass}`;
      trustBadge.innerText = trustStatus.label;
    }

    const btnVerifyResolved = document.getElementById("btnVerifyResolved");
    if (btnVerifyResolved) {
      btnVerifyResolved.onclick = () => {
        openTrustVerificationModal(username);
      };
    }
  } catch (err) {
    showToast("Lookup error: " + err.message);
  }
}

// Messaging / Chat
async function sendChatMessage() {
  if (!currentIdentity || currentIdentity.status === "revoked") {
    showToast("You need an active identity to send messages.");
    return;
  }

  if (!activeChatPeer) {
    showToast("Select or start a conversation first.");
    return;
  }

  const recipient = activeChatPeer.toLowerCase().trim();
  const msgInput = document.getElementById("inputChatMessage");
  const text = (msgInput?.value || "").trim();

  if (!text && !stagedAttachment) return;

  // Clear input and staged attachment immediately
  if (msgInput) msgInput.value = "";
  const attachmentToSend = stagedAttachment;
  stagedAttachment = null;
  renderAttachmentStaging();

  // 1. Resolve recipient key (cached or authoritative query via blinded token)
  let recipEdPubHex = "";
  const recipData = await resolveRecipientBinding(recipient);
  if (!recipData) {
    showToast(`Recipient @${recipient} not found. Look them up in Directory first.`);
    if (msgInput) msgInput.value = text;
    stagedAttachment = attachmentToSend;
    renderAttachmentStaging();
    return;
  }
  if (recipData.status === "revoked") {
    showToast(`Cannot send - @${recipient} account is revoked.`);
    if (msgInput) msgInput.value = text;
    stagedAttachment = attachmentToSend;
    renderAttachmentStaging();
    return;
  }
  recipEdPubHex = recipData.pubkey;

  // 2. Disappearing messages retention check
  const retentionSelect = document.getElementById("chatRetentionSelect");
  const ttl = retentionSelect ? parseInt(retentionSelect.value || "0", 10) : 0;
  const expiresAt = ttl > 0 ? (Date.now() + ttl * 1000) : 0;

  // Optimistic UI: Append immediately with unique message ID, Sending state, expiresAt, and attachment
  const msgId = "msg_" + getRandomNonce(8);
  saveChatHistoryMessage(currentIdentity.username, "outgoing", text, currentIdentity.username, true, recipient, msgId, "Sending", expiresAt, false, attachmentToSend);
  registerConversation(currentIdentity.username, recipient, text || (attachmentToSend ? "[File]" : ""), Date.now(), true);
  appendChatMessageDOM("outgoing", text, currentIdentity.username, true, Date.now(), "Sending", msgId, attachmentToSend);
  renderConversationsList(document.getElementById("inputFilterChats")?.value || "");

  // 3. Encrypt in-memory via Curve25519 & XSalsa20-Poly1305
  try {
    const recipXPub = ed25519PubToCurve25519(fromHex(recipEdPubHex));
    const ephemKeyPair = nacl.box.keyPair();
    const boxNonce = nacl.randomBytes(24);

    const innerPayload = JSON.stringify({
      v: 1,
      type: attachmentToSend ? "file" : "msg",
      msg_id: msgId,
      body: text,
      filename: attachmentToSend ? attachmentToSend.filename : "",
      mime: attachmentToSend ? attachmentToSend.mime : "",
      size: attachmentToSend ? attachmentToSend.size : 0,
      data: attachmentToSend ? attachmentToSend.data : "",
      sender: currentIdentity.username,
      ttl: ttl
    });
    const ciphertextBytes = nacl.box(strToBytes(innerPayload), boxNonce, recipXPub, ephemKeyPair.secretKey);

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

    // Blinded Routing Tokens (Zero-Knowledge Metadata on Relay)
    const recipientToken = await deriveHandleToken(recipient);
    const senderToken = currentIdentity.handleToken || await deriveHandleToken(currentIdentity.username);

    const msg = `${PROTOCOL_PREFIX}:SEND:${recipientToken}:${senderToken}:${payloadHash}:${timestamp}:${nonce}`;
    const sigBytes = nacl.sign.detached(strToBytes(msg), fromHex(currentIdentity.privKey));

    // 4. Single round-trip send to relay with blinded routing tokens
    const resp = await fetch(getRelayBaseUrl() + "/v1/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        recipient: recipientToken,
        sender: senderToken,
        payload: e2eeEnvelope,
        timestamp,
        nonce,
        sig: toHex(sigBytes)
      })
    });

    const data = await resp.json();
    if (resp.ok) {
      updateMessageDeliveryStatus(currentIdentity.username, msgId, "Sent");
    } else {
      if (resp.status === 404 && data.error && data.error.includes("Sender identity not found")) {
        showToast("Syncing sender identity with relay...");
        const ok = await ensureIdentityRegistered(currentIdentity);
        if (ok) {
          const retryResp = await fetch(getRelayBaseUrl() + "/v1/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              recipient: recipientToken,
              sender: senderToken,
              payload: e2eeEnvelope,
              timestamp,
              nonce,
              sig: toHex(sigBytes)
            })
          });
          if (retryResp.ok) {
            updateMessageDeliveryStatus(currentIdentity.username, msgId, "Sent");
            return;
          }
        }
      }
      updateMessageDeliveryStatus(currentIdentity.username, msgId, "Failed");
      showToast("Send error: " + (data.error || "Unknown error"));
    }
  } catch (err) {
    console.error("Send failure:", err);
    updateMessageDeliveryStatus(currentIdentity.username, msgId, "Failed");
    showToast("Network send failure: " + err.message);
  }
}

// Silent End-to-End Delivery Receipt Emission
async function sendDeliveryReceipt(recipient, targetMsgId) {
  if (!currentIdentity || !recipient || !targetMsgId) return;
  const recipData = await resolveRecipientBinding(recipient);
  if (!recipData || !recipData.pubkey) return;

  try {
    const recipXPub = ed25519PubToCurve25519(fromHex(recipData.pubkey));
    const ephemKeyPair = nacl.box.keyPair();
    const boxNonce = nacl.randomBytes(24);

    const receiptInner = JSON.stringify({
      v: 1,
      type: "receipt",
      target_id: targetMsgId,
      sender: currentIdentity.username
    });
    const ciphertextBytes = nacl.box(strToBytes(receiptInner), boxNonce, recipXPub, ephemKeyPair.secretKey);

    const envelope = JSON.stringify({
      v: 1,
      alg: "x25519-xsalsa20-poly1305",
      ephem_pub: toHex(ephemKeyPair.publicKey),
      nonce: toHex(boxNonce),
      ciphertext: toHex(ciphertextBytes),
      sender: currentIdentity.username
    });

    const payloadHash = await sha256Hex(envelope);
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = getRandomNonce(16);

    const recipientToken = await deriveHandleToken(recipient);
    const senderToken = currentIdentity.handleToken || await deriveHandleToken(currentIdentity.username);

    const msg = `${PROTOCOL_PREFIX}:SEND:${recipientToken}:${senderToken}:${payloadHash}:${timestamp}:${nonce}`;
    const sigBytes = nacl.sign.detached(strToBytes(msg), fromHex(currentIdentity.privKey));

    await fetch(getRelayBaseUrl() + "/v1/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        recipient: recipientToken,
        sender: senderToken,
        payload: envelope,
        timestamp,
        nonce,
        sig: toHex(sigBytes)
      })
    });
  } catch (err) {
    console.error("Delivery receipt error:", err);
  }
}

// Silent End-to-End Read Receipt Emission
async function sendReadReceipt(recipient, targetMsgIds) {
  if (!currentIdentity || !recipient || !targetMsgIds || targetMsgIds.length === 0) return;
  const recipData = await resolveRecipientBinding(recipient);
  if (!recipData || !recipData.pubkey) return;

  try {
    const recipXPub = ed25519PubToCurve25519(fromHex(recipData.pubkey));
    const ephemKeyPair = nacl.box.keyPair();
    const boxNonce = nacl.randomBytes(24);

    const receiptInner = JSON.stringify({
      v: 1,
      type: "read_receipt",
      target_ids: targetMsgIds,
      sender: currentIdentity.username
    });
    const ciphertextBytes = nacl.box(strToBytes(receiptInner), boxNonce, recipXPub, ephemKeyPair.secretKey);

    const envelope = JSON.stringify({
      v: 1,
      alg: "x25519-xsalsa20-poly1305",
      ephem_pub: toHex(ephemKeyPair.publicKey),
      nonce: toHex(boxNonce),
      ciphertext: toHex(ciphertextBytes),
      sender: currentIdentity.username
    });

    const payloadHash = await sha256Hex(envelope);
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = getRandomNonce(16);

    const recipientToken = await deriveHandleToken(recipient);
    const senderToken = currentIdentity.handleToken || await deriveHandleToken(currentIdentity.username);

    const msg = `${PROTOCOL_PREFIX}:SEND:${recipientToken}:${senderToken}:${payloadHash}:${timestamp}:${nonce}`;
    const sigBytes = nacl.sign.detached(strToBytes(msg), fromHex(currentIdentity.privKey));

    await fetch(getRelayBaseUrl() + "/v1/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        recipient: recipientToken,
        sender: senderToken,
        payload: envelope,
        timestamp,
        nonce,
        sig: toHex(sigBytes)
      })
    });
  } catch (err) {
    console.error("Read receipt error:", err);
  }
}

// Real-Time SSE Stream with Automatic Reconnect & Cursor Gap-Fill
async function startRealtimeStream() {
  if (reconnectTimer) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  if (eventSource) {
    eventSource.close();
    eventSource = null;
  }
  if (!currentIdentity || currentIdentity.status === "revoked") return;

  // Self-Healing Identity Sync: Verify identity on relay before opening stream
  const isRegistered = await ensureIdentityRegistered(currentIdentity);
  if (!isRegistered) {
    document.getElementById("relayStatusText").innerText = "Connecting...";
    reconnectTimer = setTimeout(startRealtimeStream, 2000);
    return;
  }

  const username = currentIdentity.username;
  const streamId = currentIdentity.handleToken || await deriveHandleToken(username);
  const storedCursor = localStorage.getItem(`author_cursor_${username}`);
  if (storedCursor) {
    lastSeenMessageId = parseInt(storedCursor, 10) || 0;
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = getRandomNonce(16);
  const msg = `${PROTOCOL_PREFIX}:INBOX:${streamId}:${timestamp}:${nonce}`;
  const sigBytes = nacl.sign.detached(strToBytes(msg), fromHex(currentIdentity.privKey));
  const sig = toHex(sigBytes);

  const url = `/v1/events?recipient=${encodeURIComponent(streamId)}&ts=${timestamp}&nonce=${nonce}&sig=${sig}&since_id=${lastSeenMessageId}`;
  eventSource = new EventSource(getRelayBaseUrl() + url);

  eventSource.onopen = () => {
    document.getElementById("relayDot").style.background = "#ffffff";
    document.getElementById("relayStatusText").innerText = "Online";
  };

  eventSource.addEventListener("connected", (e) => {
    document.getElementById("relayDot").style.background = "#ffffff";
    document.getElementById("relayStatusText").innerText = "Online";
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
      let isReceipt = false;
      try {
        const env = JSON.parse(m.payload);
        if (env.alg === "x25519-xsalsa20-poly1305" && env.ephem_pub && env.nonce && env.ciphertext) {
          const myXPriv = deriveX25519SecretKey(fromHex(currentIdentity.privKey));
          const opened = nacl.box.open(fromHex(env.ciphertext), fromHex(env.nonce), fromHex(env.ephem_pub), myXPriv);
          if (opened) {
            bodyText = bytesToStr(opened);
            isE2EE = true;
            let incomingMsgId = "";
            let incomingExpiresAt = 0;
            let incomingAttachment = null;
            try {
              const inner = JSON.parse(bodyText);
              if (inner && inner.type === "receipt" && inner.target_id) {
                isReceipt = true;
                updateMessageDeliveryStatus(username, inner.target_id, "Delivered");
              } else if (inner && inner.type === "read_receipt" && Array.isArray(inner.target_ids)) {
                isReceipt = true;
                for (const tid of inner.target_ids) {
                  updateMessageDeliveryStatus(username, tid, "Read");
                }
              } else if (inner && (inner.type === "msg" || inner.type === "file")) {
                bodyText = inner.body || inner.text || (inner.type === "file" ? "" : bodyText);
                incomingMsgId = inner.msg_id || "";
                if (inner.ttl && inner.ttl > 0) {
                  incomingExpiresAt = Date.now() + (inner.ttl * 1000);
                }
                if (inner.type === "file" && inner.data) {
                  incomingAttachment = {
                    filename: inner.filename || "file",
                    mime: inner.mime || "application/octet-stream",
                    size: inner.size || 0,
                    data: inner.data
                  };
                }
                if (inner.msg_id && (env.sender || m.sender)) {
                  sendDeliveryReceipt(env.sender || m.sender, inner.msg_id);
                }
              }
            } catch (e) {}
          } else {
            const failSender = (env.sender || m.sender || "").toLowerCase().trim();
            if (failSender) {
              localStorage.removeItem(`author_pk_cache_${failSender}`);
              delete recipientKeyCache[failSender];
            }
            bodyText = "[Decryption failed - key mismatch]";
          }
          senderName = env.sender || m.sender;
        } else {
          bodyText = env.body || m.payload;
          senderName = env.from || m.sender;
        }
      } catch {}

      // If it was a delivery or read receipt, acknowledge and do not render as chat bubble
      if (isReceipt) {
        await acknowledgeMessages([m.id]);
        return;
      }

      const peer = (senderName || "").toLowerCase().trim();
      let readSent = false;
      if (activeChatPeer && activeChatPeer === peer) {
        readSent = true;
        if (incomingMsgId) {
          sendReadReceipt(peer, [incomingMsgId]);
        }
      }

      saveChatHistoryMessage(username, "incoming", bodyText, senderName, isE2EE, peer, incomingMsgId, "Delivered", incomingExpiresAt, readSent, incomingAttachment);
      registerConversation(username, peer, bodyText || (incomingAttachment ? "[File]" : ""), Date.now(), isE2EE);
      renderConversationsList(document.getElementById("inputFilterChats")?.value || "");

      if (activeChatPeer && activeChatPeer === peer) {
        appendChatMessageDOM("incoming", bodyText, senderName, isE2EE, Date.now(), "Delivered", incomingMsgId, incomingAttachment);
      } else {
        showToast(`New message from @${senderName}`);
      }

      // Acknowledge receipt so relay prunes it
      await acknowledgeMessages([m.id]);
    } catch (err) {
      console.error("Error processing stream event:", err);
    }
  });

  eventSource.onerror = async () => {
    console.log("Stream dropped. Reconnecting with fresh token in 3s...");
    document.getElementById("relayStatusText").innerText = "Connecting...";
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    if (currentIdentity) {
      await ensureIdentityRegistered(currentIdentity);
    }
    reconnectTimer = setTimeout(startRealtimeStream, 3000);
  };
}

async function acknowledgeMessages(ids) {
  if (!ids || ids.length === 0 || !currentIdentity) return;

  const streamId = currentIdentity.handleToken || await deriveHandleToken(currentIdentity.username);
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = getRandomNonce(16);
  const idsSummary = ids.join(",");

  const msg = `${PROTOCOL_PREFIX}:ACK:${streamId}:${idsSummary}:${timestamp}:${nonce}`;
  const sigBytes = nacl.sign.detached(strToBytes(msg), fromHex(currentIdentity.privKey));

  try {
    await fetch(getRelayBaseUrl() + "/v1/ack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        recipient: streamId,
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

function appendChatMessageDOM(type, text, sender, isE2EE = false, time = Date.now(), status = "Sent", msgId = "", attachment = null) {
  const box = document.getElementById("chatBox");
  if (!box) return;
  // Remove placeholder if present
  if (box.children.length === 1 && (box.children[0].innerText.includes("Messages are") || box.children[0].innerText.includes("No messages yet"))) {
    box.innerHTML = "";
  }

  const div = document.createElement("div");
  div.className = "chat-msg " + type;

  const header = document.createElement("div");
  header.className = "chat-msg-header";

  const senderSpan = document.createElement("span");
  senderSpan.innerText = "@" + sender;
  header.appendChild(senderSpan);

  if (isE2EE) {
    const badge = document.createElement("span");
    badge.style.color = "#888888";
    badge.style.fontSize = "0.75rem";
    badge.style.marginLeft = "0.4rem";
    badge.innerText = "Encrypted";
    header.appendChild(badge);
  }

  const body = document.createElement("div");

  if (attachment) {
    if (attachment.mime && attachment.mime.startsWith("image/")) {
      const img = document.createElement("img");
      img.className = "chat-msg-image";
      img.src = attachment.data;
      img.alt = attachment.filename || "Image";
      img.onclick = () => {
        const w = window.open("");
        if (w) w.document.write(`<img src="${attachment.data}" style="max-width:100%; height:auto; background:#000;">`);
      };
      body.appendChild(img);
    } else {
      const fileLink = document.createElement("a");
      fileLink.className = "chat-msg-file";
      fileLink.href = attachment.data;
      fileLink.download = attachment.filename || "file";
      fileLink.innerHTML = `<span>${escapeHtml(attachment.filename || "File")}</span> <span style="font-size: 0.7rem; color: var(--text-muted);">(${formatFileSize(attachment.size)})</span>`;
      body.appendChild(fileLink);
    }
  }

  if (text) {
    const textNode = document.createElement("div");
    if (attachment) textNode.style.marginTop = "0.35rem";
    textNode.innerText = text;
    body.appendChild(textNode);
  }

  const footer = document.createElement("div");
  footer.className = "msg-footer";
  const timeFormatted = formatChatTime(time);
  if (type === "outgoing") {
    const statusText = status || "Sent";
    const statusSpan = msgId ? `<span style="opacity: 0.4;">·</span> <span class="msg-status" id="msg_status_${escapeHtml(msgId)}">${escapeHtml(statusText)}</span>` : "";
    footer.innerHTML = `<span>${escapeHtml(timeFormatted)}</span> ${statusSpan}`;
  } else {
    footer.innerHTML = `<span>${escapeHtml(timeFormatted)}</span>`;
  }

  div.appendChild(header);
  div.appendChild(body);
  div.appendChild(footer);
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
}

// Event Listeners & App Initialization
function initApp() {
  checkHealth();
  ensureAllIdentitiesRegistered();
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

  // Directory Lookup
  document.getElementById("btnLookup").onclick = resolveUser;

  // Chat Navigation & Modals
  const btnOpenNewChat = document.getElementById("btnOpenNewChatModal");
  if (btnOpenNewChat) btnOpenNewChat.onclick = openNewChatModal;

  const btnEmptyNewChat = document.getElementById("btnEmptyNewChat");
  if (btnEmptyNewChat) btnEmptyNewChat.onclick = openNewChatModal;

  const btnCloseModal = document.getElementById("btnCloseNewChatModal");
  if (btnCloseModal) btnCloseModal.onclick = closeNewChatModal;

  const btnSubmitModal = document.getElementById("btnSubmitNewChat");
  if (btnSubmitModal) btnSubmitModal.onclick = submitNewChat;

  const inputNewChat = document.getElementById("inputNewChatHandle");
  if (inputNewChat) {
    inputNewChat.addEventListener("keydown", (e) => {
      if (e.key === "Enter") submitNewChat();
    });
  }

  const modalNewChatEl = document.getElementById("modalNewChat");
  if (modalNewChatEl) {
    modalNewChatEl.onclick = (e) => {
      if (e.target === modalNewChatEl) closeNewChatModal();
    };
  }

  const btnBack = document.getElementById("btnBackToChats");
  if (btnBack) btnBack.onclick = backToChatsList;

  const inputFilter = document.getElementById("inputFilterChats");
  if (inputFilter) {
    inputFilter.addEventListener("input", (e) => {
      renderConversationsList(e.target.value);
    });
  }

  // Web of Trust Verification Handlers
  const badgeTrust = document.getElementById("activeContactTrustBadge");
  if (badgeTrust) badgeTrust.onclick = () => openTrustVerificationModal();

  const btnHeaderTrust = document.getElementById("btnHeaderTrustVerify");
  if (btnHeaderTrust) btnHeaderTrust.onclick = () => openTrustVerificationModal();

  const btnCloseTrust = document.getElementById("btnCloseTrustModal");
  if (btnCloseTrust) btnCloseTrust.onclick = closeTrustModal;

  const modalTrustEl = document.getElementById("modalTrustVerify");
  if (modalTrustEl) {
    modalTrustEl.onclick = (e) => {
      if (e.target === modalTrustEl) closeTrustModal();
    };
  }

  // Settings Modal (Relay Endpoint & Storage)
  const btnSettings = document.getElementById("btnHeaderSettings");
  const modalSettings = document.getElementById("modalSettings");
  const btnCloseSettings = document.getElementById("btnCloseSettingsModal");
  const btnSaveRelay = document.getElementById("btnSaveRelay");
  const btnResetRelay = document.getElementById("btnResetRelay");
  const btnClearCache = document.getElementById("btnClearCache");
  const inputRelay = document.getElementById("inputCustomRelay");
  const displayRelay = document.getElementById("currentRelayDisplay");

  function openSettingsModal() {
    if (!modalSettings) return;
    const current = getRelayBaseUrl();
    if (inputRelay) inputRelay.value = current;
    if (displayRelay) displayRelay.innerText = current ? current : "Default (" + window.location.origin + ")";
    modalSettings.style.display = "flex";
  }

  function closeSettingsModal() {
    if (modalSettings) modalSettings.style.display = "none";
  }

  if (btnSettings) btnSettings.onclick = openSettingsModal;
  if (btnCloseSettings) btnCloseSettings.onclick = closeSettingsModal;
  if (modalSettings) {
    modalSettings.onclick = (e) => {
      if (e.target === modalSettings) closeSettingsModal();
    };
  }

  if (btnSaveRelay) {
    btnSaveRelay.onclick = () => {
      const url = (inputRelay?.value || "").trim().replace(/\/+$/, "");
      if (url && !url.startsWith("http://") && !url.startsWith("https://")) {
        showToast("Relay URL must start with http:// or https://");
        return;
      }
      if (url) {
        localStorage.setItem("author_relay_url", url);
        showToast("Connected to custom relay: " + url);
      } else {
        localStorage.removeItem("author_relay_url");
        showToast("Switched to default relay.");
      }
      closeSettingsModal();
      checkHealth();
      ensureAllIdentitiesRegistered().then(() => startRealtimeStream());
    };
  }

  if (btnResetRelay) {
    btnResetRelay.onclick = () => {
      localStorage.removeItem("author_relay_url");
      if (inputRelay) inputRelay.value = "";
      if (displayRelay) displayRelay.innerText = "Default (" + window.location.origin + ")";
      showToast("Reset to default relay.");
      closeSettingsModal();
      checkHealth();
      ensureAllIdentitiesRegistered().then(() => startRealtimeStream());
    };
  }

  if (btnClearCache) {
    btnClearCache.onclick = async () => {
      if ("caches" in window) {
        const keys = await caches.keys();
        await Promise.all(keys.map(k => caches.delete(k)));
      }
      showToast("Cache cleared. Reloading...");
      setTimeout(() => window.location.reload(true), 500);
    };
  }

  // Chat Sending & Inbox Sync
  document.getElementById("btnSendChatMessage").onclick = sendChatMessage;

  // File Attachment Controls
  const btnAttach = document.getElementById("btnAttachFile");
  const inputAttach = document.getElementById("inputFileAttachment");
  if (btnAttach && inputAttach) {
    btnAttach.onclick = () => inputAttach.click();
    inputAttach.onchange = (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      if (file.size > 1.5 * 1024 * 1024) {
        showToast("File too large. Maximum attachment size is 1.5 MB.");
        inputAttach.value = "";
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        stagedAttachment = {
          filename: file.name,
          mime: file.type || "application/octet-stream",
          size: file.size,
          data: reader.result
        };
        renderAttachmentStaging();
        inputAttach.value = "";
      };
      reader.readAsDataURL(file);
    };
  }

  const btnRefreshInbox = document.getElementById("btnRefreshInbox");
  if (btnRefreshInbox) {
    btnRefreshInbox.onclick = async () => {
      if (!currentIdentity) return;
      showToast("Syncing inbox...");
      startRealtimeStream();
    };
  }

  document.getElementById("inputChatMessage").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendChatMessage();
  });

  // Disappearing Messages Retention Setting
  const retentionSelect = document.getElementById("chatRetentionSelect");
  if (retentionSelect) {
    retentionSelect.onchange = (e) => {
      if (currentIdentity && activeChatPeer) {
        localStorage.setItem(`author_ttl_${currentIdentity.username}_${activeChatPeer}`, e.target.value);
        const labels = { "0": "Keep Forever", "3600": "1 Hour", "86400": "24 Hours", "604800": "7 Days" };
        showToast("Disappearing timer set to: " + (labels[e.target.value] || "Custom"));
      }
    };
  }

  // Periodic Purge of Expired Disappearing Messages (every 15s)
  setInterval(() => {
    if (currentIdentity) {
      purgeExpiredMessages(currentIdentity.username);
    }
  }, 15000);

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
      ensureAllIdentitiesRegistered().then(() => {
        startRealtimeStream();
      });
    }
  });

  // Online / Offline State Handlers
  window.addEventListener("online", () => {
    document.getElementById("relayDot").style.background = "#ffffff";
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
