import {
  createButton,
  createInput,
  createRow,
  createSection,
  styleInputBase,
  toErrorText,
} from './dom';
import { generateMnemonic, mnemonicToPrivateKeyHex } from './mnemonic';
import {
  createAccount,
  getPublicKeyByNumber,
  registerEmail,
  resolveSeed,
  sendCallAuthChallenge,
  sendCallAuthOK,
  sendCallAuthResponse,
  sendCallHangup,
  sendCallReject,
  resetDo,
  resetRequest,
  sendICEAnswer,
  sendICECandidate,
  sendICEOffer,
  sendSMS,
} from './api';
import type { NodeInbound, ScreenKey } from './types';
import { PointPairSchnorrP256 } from './ecdsa';

let windowBase = 'https://WINDOW_SERVER_HOST:30000';
let nodeWsUrl = '';
let nodeSocket: WebSocket | null = null;
let currentNumber = '';
let currentChallenge = '';
let isAuthenticated = false;
// currentPrivateKeyHex はセッション中のみメモリに保持する秘密鍵（永続化しない）。
// persist=off の場合でも通話認証・SMS署名に使用できるようにする。
let currentPrivateKeyHex = '';
let pendingChallengeResolver: ((challenge: string) => void) | null = null;
let pendingAuthResolver: (() => void) | null = null;

let statusNode: HTMLDivElement | null = null;
let inboxNode: HTMLPreElement | null = null;
let signalInboxNode: HTMLPreElement | null = null;
let toastHostNode: HTMLDivElement | null = null;
let messageFeedNode: HTMLDivElement | null = null;
let threadListNode: HTMLDivElement | null = null;
let setActiveScreenRef: ((key: ScreenKey) => void) | null = null;
let syncAuthUIRef: (() => void) | null = null;
let syncMessageFeedRef: ((messages: unknown[]) => void) | null = null;
let activeScreenKey: ScreenKey = 'login';

let callPeer: RTCPeerConnection | null = null;
let localStream: MediaStream | null = null;
let remoteAudioNode: HTMLAudioElement | null = null;
let activeCallPeer = '';
// remoteDescriptionが設定される前に届いたICE candidateをバッファする
let pendingIceCandidates: RTCIceCandidateInit[] = [];
let pendingCallAuth:
  | {
      peer: string;
      challenge: string;
      publicKeyHex: string;
    }
  | null = null;

type CallPhase = 'idle' | 'dialing' | 'ringing' | 'verifying' | 'in_call' | 'ended';
let callPhase: CallPhase = 'idle';
let syncCallUIRef: ((phase: CallPhase, note?: string) => void) | null = null;
let syncCallRuntimeRef: (() => void) | null = null;

let callStartedAt = 0;
let callTimerId: number | null = null;
let localMicMuted = false;
let micAudioCtx: AudioContext | null = null;
let micMeterRafId: number | null = null;
let updateMicLevelRef: ((level: number) => void) | null = null;

let lastToastKey = '';
let lastToastAt = 0;
let lastToastCount = 0;

const LS_WINDOW_BASE = 'smsandtell.windowBase';
const LS_NUMBER = 'smsandtell.number';
const LS_PHONE_NUMBER = 'smsandtell.phoneNumber';
const LS_PRIVATE_KEY = 'smsandtell.privateKey'; // legacy: plain-text key (migration only)
const LS_ENCRYPTED_KEY = 'smsandtell.encryptedKey'; // v1:<saltHex>:<ivHex>:<ciphertextHex>
const LS_PUBLIC_KEY = 'smsandtell.publicKey';
const LS_PERSIST_SENSITIVE = 'smsandtell.persistSensitive';
const CHAT_DB_NAME = 'smsandtell-chat';
const CHAT_DB_VERSION = 1;
const CHAT_DB_STORE = 'threads';

type ChatItem = {
  id: string;
  from: string;
  to: string;
  body: string;
  timestamp: number;
  direction: 'in' | 'out';
  status: 'sending' | 'sent' | 'failed' | 'received';
  reason?: string;
};

type ChatThreadRecord = {
  owner: string;
  updatedAt: number;
  items: ChatItem[];
  contacts: Record<string, string>;
};

let chatDBPromise: Promise<IDBDatabase> | null = null;

function openChatDB(): Promise<IDBDatabase> {
  if (chatDBPromise) return chatDBPromise;
  chatDBPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(CHAT_DB_NAME, CHAT_DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(CHAT_DB_STORE)) {
        db.createObjectStore(CHAT_DB_STORE, { keyPath: 'owner' });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb open failed'));
  });
  return chatDBPromise;
}

async function loadThread(owner: string): Promise<ChatThreadRecord | null> {
  if (!owner) return null;
  const db = await openChatDB();
  return await new Promise((resolve, reject) => {
    const tx = db.transaction(CHAT_DB_STORE, 'readonly');
    const store = tx.objectStore(CHAT_DB_STORE);
    const req = store.get(owner);
    req.onsuccess = () => resolve((req.result as ChatThreadRecord | undefined) ?? null);
    req.onerror = () => reject(req.error ?? new Error('indexeddb get failed'));
  });
}

async function saveThread(owner: string, items: ChatItem[], contacts: Record<string, string>): Promise<void> {
  if (!owner) return;
  const db = await openChatDB();
  const record: ChatThreadRecord = {
    owner,
    updatedAt: Date.now(),
    items: items.slice(-500),
    contacts,
  };
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction(CHAT_DB_STORE, 'readwrite');
    const store = tx.objectStore(CHAT_DB_STORE);
    const req = store.put(record);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error ?? new Error('indexeddb put failed'));
  });
}

const signer = new PointPairSchnorrP256();

function setStatus(text: string): void {
  if (statusNode) statusNode.textContent = text;
}

function mapErrorToCode(message: string): { code: string; user: string; technical: string } {
  const m = message.toLowerCase();
  if (m.includes('private key') || m.includes('秘密鍵')) {
    return { code: 'AUTH_001', user: '秘密鍵の形式が正しくない', technical: message };
  }
  if (m.includes('auth timeout') || m.includes('challenge timeout')) {
    return { code: 'AUTH_002', user: '認証がタイムアウトした', technical: message };
  }
  if (m.includes('dns') || m.includes('record not found') || m.includes('resolve')) {
    return { code: 'NET_001', user: '接続先の解決に失敗した', technical: message };
  }
  if (m.includes('ws not connected') || m.includes('connect failed')) {
    return { code: 'NET_002', user: 'ノード接続に失敗した', technical: message };
  }
  if (m.includes('signature') || m.includes('認証失敗')) {
    return { code: 'CALL_001', user: '通話相手の認証に失敗した', technical: message };
  }
  if (m.includes('required') || m.includes('必須')) {
    return { code: 'UI_001', user: '入力必須項目を確認して', technical: message };
  }
  return { code: 'GEN_001', user: 'エラーが発生した', technical: message };
}

function showErrorToast(message: string): void {
  if (!toastHostNode) return;
  const now = Date.now();
  if (lastToastKey === message && now - lastToastAt < 1800) {
    lastToastCount += 1;
    const latest = toastHostNode.lastElementChild as HTMLDivElement | null;
    if (latest) {
      latest.textContent = `${message} (x${lastToastCount})`;
    }
    lastToastAt = now;
    return;
  }
  lastToastKey = message;
  lastToastAt = now;
  lastToastCount = 1;

  const toast = document.createElement('div');
  toast.textContent = message;
  toast.style.background = '#b42318';
  toast.style.color = '#ffffff';
  toast.style.borderRadius = '10px';
  toast.style.padding = '10px 12px';
  toast.style.fontSize = '12px';
  toast.style.boxShadow = '0 8px 24px rgba(0, 0, 0, 0.22)';
  toast.style.opacity = '0';
  toast.style.transform = 'translateY(-8px)';
  toast.style.transition = 'opacity 0.2s ease, transform 0.2s ease';
  toastHostNode.appendChild(toast);

  requestAnimationFrame(() => {
    toast.style.opacity = '1';
    toast.style.transform = 'translateY(0)';
  });

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(-8px)';
    setTimeout(() => {
      if (toast.parentElement) toast.remove();
    }, 240);
  }, 2800);
}

function setErrorStatus(err: unknown): void {
  const raw = typeof err === 'string' ? err : toErrorText(err);
  const mapped = mapErrorToCode(raw);
  setStatus(`[${mapped.code}] ${mapped.technical}`);
  showErrorToast(`[${mapped.code}] ${mapped.user}`);
}

function refreshAuthState(): void {
  if (syncAuthUIRef) syncAuthUIRef();
  if (syncCallUIRef) syncCallUIRef(callPhase);
}

function setCallPhase(phase: CallPhase, note?: string): void {
  const prev = callPhase;
  callPhase = phase;
  if (phase === 'in_call' && prev !== 'in_call') {
    callStartedAt = Date.now();
  }
  if (phase !== 'in_call') {
    callStartedAt = 0;
  }
  if (syncCallUIRef) {
    syncCallUIRef(phase, note);
  }
  if (syncCallRuntimeRef) {
    syncCallRuntimeRef();
  }
}

function ensureAuthenticated(): void {
  if (!isAuthenticated) {
    throw new Error('ログイン認証が必要です（challenge -> 署名送信を実行）');
  }
}

function closeNodeWS(): void {
  if (nodeSocket) {
    nodeSocket.close();
    nodeSocket = null;
  }
  isAuthenticated = false;
  currentPrivateKeyHex = '';
  pendingChallengeResolver = null;
  pendingAuthResolver = null;
  pendingCallAuth = null;
  cleanupCall();
  setCallPhase('idle');
  refreshAuthState();
  if (setActiveScreenRef) {
    setActiveScreenRef('login');
  }
}

function openNodeWS(number: string): Promise<void> {
  return new Promise((resolve, reject) => {
    closeNodeWS();

    if (!nodeWsUrl) {
      reject(new Error('node ws url is empty'));
      return;
    }

    const ws = new WebSocket(nodeWsUrl);
    ws.onopen = () => {
      ws.send(number);
      nodeSocket = ws;
      resolve();
    };

    ws.onerror = () => {
      reject(new Error('node ws connect failed'));
    };

    ws.onclose = () => {
      if (nodeSocket !== ws) {
        // すでに別のソケットに置き換えられているか、closeNodeWSで処理済み
        setStatus('node ws closed');
        return;
      }
      nodeSocket = null;
      if (isAuthenticated) {
        isAuthenticated = false;
        pendingChallengeResolver = null;
        pendingAuthResolver = null;
        pendingCallAuth = null;
        cleanupCall();
        setCallPhase('idle');
        refreshAuthState();
        if (setActiveScreenRef) setActiveScreenRef('login');
      }
      setStatus('node ws closed');
    };

    ws.onmessage = (event) => {
      let data: NodeInbound;
      try {
        data = JSON.parse(String(event.data)) as NodeInbound;
      } catch {
        // サーバーから不正なJSONが届いた場合は無視して接続を維持する
        return;
      }

      if (data.challenge) {
        currentChallenge = String(data.challenge);
        if (pendingChallengeResolver) {
          pendingChallengeResolver(currentChallenge);
          pendingChallengeResolver = null;
        }
        setStatus('challenge received');
        return;
      }

      if (data.action === 'messages') {
        if (inboxNode) {
          inboxNode.textContent = JSON.stringify(data.messages ?? [], null, 2);
        }
        if (syncMessageFeedRef) {
          syncMessageFeedRef(data.messages ?? []);
        }
        setStatus('messages received');
        return;
      }

      if (data.action === 'ice_offer' || data.action === 'ice_answer' || data.action === 'ice_candidate') {
        if (signalInboxNode) {
          const pretty = JSON.stringify(data.data ?? {}, null, 2);
          const old = signalInboxNode.textContent ?? '';
          signalInboxNode.textContent = `${data.action}\n${pretty}\n\n${old}`.trim();
        }
        handleSignalAction(String(data.action), data.data).catch((err: unknown) => setErrorStatus(err));
        return;
      }

      if (
        data.action === 'call_auth_challenge' ||
        data.action === 'call_auth_response' ||
        data.action === 'call_reject' ||
        data.action === 'call_auth_ok' ||
        data.action === 'call_hangup'
      ) {
        if (signalInboxNode) {
          const pretty = JSON.stringify(data.data ?? {}, null, 2);
          const old = signalInboxNode.textContent ?? '';
          signalInboxNode.textContent = `${data.action}\n${pretty}\n\n${old}`.trim();
        }
        handleSignalAction(String(data.action), data.data).catch((err: unknown) => setErrorStatus(err));
        return;
      }

      if (data.status) {
        if (data.status === 'authenticated') {
          isAuthenticated = true;
          refreshAuthState();
          if (pendingAuthResolver) {
            pendingAuthResolver();
            pendingAuthResolver = null;
          }
        }
        setStatus(`node: ${String(data.status)}`);
        return;
      }

      if (data.error) {
        setErrorStatus(`node error: ${String(data.error)}`);
      }
    };
  });
}

function requestChallenge(): void {
  if (!nodeSocket) {
    setStatus('ws not connected');
    return;
  }
  nodeSocket.send(JSON.stringify({ action: 'challenge' }));
}

function sendAuthVerify(signatureHex: string): void {
  if (!nodeSocket) {
    setStatus('ws not connected');
    return;
  }
  if (!currentChallenge) {
    setStatus('challenge not ready');
    return;
  }
  nodeSocket.send(
    JSON.stringify({
      action: 'auth_verify',
      challenge: currentChallenge,
      sig: signatureHex,
    }),
  );
}

function requestChallengeOnce(timeoutMs = 6000): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!nodeSocket) {
      reject(new Error('ws not connected'));
      return;
    }
    const timer = setTimeout(() => {
      pendingChallengeResolver = null;
      reject(new Error('challenge timeout'));
    }, timeoutMs);
    pendingChallengeResolver = (challenge: string) => {
      clearTimeout(timer);
      resolve(challenge);
    };
    requestChallenge();
  });
}

function waitAuthenticated(timeoutMs = 6000): Promise<void> {
  return new Promise((resolve, reject) => {
    if (isAuthenticated) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      pendingAuthResolver = null;
      reject(new Error('auth timeout'));
    }, timeoutMs);
    pendingAuthResolver = () => {
      clearTimeout(timer);
      resolve();
    };
  });
}

function canonicalJSONStringify(value: unknown): string {
  const seen = new WeakSet<object>();
  const walk = (v: unknown): unknown => {
    if (v === null || typeof v !== 'object') return v;
    if (Array.isArray(v)) return v.map(walk);
    const obj = v as Record<string, unknown>;
    if (seen.has(obj)) throw new Error('circular object');
    seen.add(obj);
    const out: Record<string, unknown> = {};
    const keys = Object.keys(obj).sort();
    for (const k of keys) {
      out[k] = walk(obj[k]);
    }
    return out;
  };
  return JSON.stringify(walk(value));
}

function makeAuthSignatureHex(number: string, challenge: string, privateKeyHex: string): string {
  const priv = signer.hexToBytes(privateKeyHex);
  if (priv.length !== 32) {
    throw new Error('private key must be 32 bytes hex');
  }
  const payload = canonicalJSONStringify({ number, challenge });
  const msg = new TextEncoder().encode(payload);
  const pub = signer.privatekeytoPublicKey(priv);
  const sig = signer.sign(msg, priv, pub);
  return signer.bytesToHex(sig[0]) + signer.bytesToHex(sig[1]) + signer.bytesToHex(sig[2]);
}

function makeMessageSignatureHex(
  from: string,
  to: string,
  message: unknown,
  timestamp: number,
  privateKeyHex: string,
): string {
  const priv = signer.hexToBytes(privateKeyHex);
  if (priv.length !== 32) {
    throw new Error('private key must be 32 bytes hex');
  }
  const payload = canonicalJSONStringify({ timestamp, message, to, from });
  const msg = new TextEncoder().encode(payload);
  const pub = signer.privatekeytoPublicKey(priv);
  const sig = signer.sign(msg, priv, pub);
  return signer.bytesToHex(sig[0]) + signer.bytesToHex(sig[1]) + signer.bytesToHex(sig[2]);
}

function derivePublicKeyHex(privateKeyHex: string): string {
  const priv = signer.hexToBytes(privateKeyHex);
  if (priv.length !== 32) {
    throw new Error('private key must be 32 bytes hex');
  }
  const pub = signer.privatekeytoPublicKey(priv);
  return signer.bytesToHex(pub[0]) + signer.bytesToHex(pub[1]);
}

function normalizePrivateKeyHex(privateKeyHex: string): string {
  const hex = privateKeyHex.trim().toUpperCase();
  if (!/^[0-9A-F]{64}$/.test(hex)) {
    throw new Error('private key は64桁の16進文字で入力');
  }
  return hex;
}

function _bytesToHexLocal(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function _hexToBytesLocal(hex: string): Uint8Array {
  const pairs = hex.match(/.{2}/g) ?? [];
  return new Uint8Array(pairs.map(b => parseInt(b, 16)));
}

async function encryptPrivateKey(privateKeyHex: string, password: string): Promise<string> {
  const enc = new TextEncoder();
  const saltArr = new Uint8Array(16);
  crypto.getRandomValues(saltArr);
  const ivArr = new Uint8Array(12);
  crypto.getRandomValues(ivArr);
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltArr.buffer, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivArr.buffer, tagLength: 128 }, aesKey, enc.encode(privateKeyHex));
  return `v1:${_bytesToHexLocal(saltArr)}:${_bytesToHexLocal(ivArr)}:${_bytesToHexLocal(new Uint8Array(ciphertext))}`;
}

async function decryptPrivateKey(encrypted: string, password: string): Promise<string> {
  const parts = encrypted.split(':');
  if (parts.length !== 4 || parts[0] !== 'v1') throw new Error('保存済みの鍵の形式が不正です');
  const [, saltHex, ivHex, cipherHex] = parts as [string, string, string, string];
  const saltArr = _hexToBytesLocal(saltHex);
  const ivArr = _hexToBytesLocal(ivHex);
  const ciphertextArr = _hexToBytesLocal(cipherHex);
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltArr.buffer, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: ivArr.buffer, tagLength: 128 }, aesKey, ciphertextArr.buffer);
  } catch (err) {
    console.debug('decryptPrivateKey failed:', err);
    throw new Error('パスワードが違います');
  }
  return new TextDecoder().decode(plaintext);
}

function validateSavePassword(password: string): void {
  if (password.length < 8) {
    throw new Error('保存パスワードは8文字以上で入力してください');
  }
}

function createChallengeHex(): string {
  const b = new Uint8Array(32);
  crypto.getRandomValues(b);
  return Array.from(b)
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('');
}

function splitPublicKeyHex(pubHex: string): [Uint8Array, Uint8Array] {
  const norm = pubHex.trim().toUpperCase();
  if (!/^[0-9A-F]{128}$/.test(norm)) {
    throw new Error('invalid public key encoding');
  }
  const bytes = signer.hexToBytes(norm);
  return [bytes.slice(0, 32), bytes.slice(32, 64)];
}

function splitSignatureHex(sigHex: string): [Uint8Array, Uint8Array, Uint8Array] {
  const norm = sigHex.trim().toUpperCase();
  if (!/^[0-9A-F]{192}$/.test(norm)) {
    throw new Error('invalid signature encoding');
  }
  const bytes = signer.hexToBytes(norm);
  return [bytes.slice(0, 32), bytes.slice(32, 64), bytes.slice(64, 96)];
}

function verifyCallAuthSignature(number: string, challenge: string, sigHex: string, publicKeyHex: string): boolean {
  const payload = canonicalJSONStringify({ number, challenge });
  const msg = new TextEncoder().encode(payload);
  const pub = splitPublicKeyHex(publicKeyHex);
  const sig = splitSignatureHex(sigHex);
  return signer.verify(msg, pub, sig);
}

function ringUser(): void {
  try {
    const ctx = new AudioContext();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = 'sine';
    osc.frequency.value = 880;
    gain.gain.value = 0.05;
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.start();
    setTimeout(() => {
      osc.stop();
      void ctx.close();
    }, 500);
  } catch {
    // no-op if audio context is unavailable
  }
}

async function ensureLocalStream(): Promise<MediaStream> {
  if (localStream) return localStream;
  localStream = await navigator.mediaDevices.getUserMedia({ audio: true, video: false });
  if (updateMicLevelRef) {
    if (micAudioCtx) {
      void micAudioCtx.close();
      micAudioCtx = null;
    }
    const ctx = new AudioContext();
    const src = ctx.createMediaStreamSource(localStream);
    const analyser = ctx.createAnalyser();
    analyser.fftSize = 512;
    src.connect(analyser);
    const data = new Uint8Array(analyser.frequencyBinCount);
    micAudioCtx = ctx;
    const tick = () => {
      analyser.getByteTimeDomainData(data);
      let sum = 0;
      for (let i = 0; i < data.length; i += 1) {
        const sample = data[i] ?? 128;
        const v = (sample - 128) / 128;
        sum += v * v;
      }
      const rms = Math.sqrt(sum / data.length);
      updateMicLevelRef?.(Math.min(1, rms * 4));
      micMeterRafId = requestAnimationFrame(tick);
    };
    tick();
  }
  return localStream;
}

function cleanupCall(): void {
  if (callPeer) {
    callPeer.onicecandidate = null;
    callPeer.ontrack = null;
    callPeer.close();
    callPeer = null;
  }
  if (localStream) {
    for (const track of localStream.getTracks()) {
      track.stop();
    }
    localStream = null;
  }
  if (micMeterRafId) {
    cancelAnimationFrame(micMeterRafId);
    micMeterRafId = null;
  }
  if (micAudioCtx) {
    void micAudioCtx.close();
    micAudioCtx = null;
  }
  activeCallPeer = '';
  pendingIceCandidates = [];
  localMicMuted = false;
  if (syncCallRuntimeRef) {
    syncCallRuntimeRef();
  }
}

async function ensurePeerForTarget(target: string): Promise<RTCPeerConnection> {
  if (!target) throw new Error('missing call target');
  if (callPeer && activeCallPeer === target) return callPeer;
  cleanupCall();
  const pc = new RTCPeerConnection({
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      { urls: 'stun:stun2.l.google.com:19302' },
      { urls: 'stun:stun3.l.google.com:19302' },
      { urls: 'stun:stun4.l.google.com:19302' },
    ],
    iceCandidatePoolSize: 10,
  });
  const stream = await ensureLocalStream();
  for (const track of stream.getTracks()) {
    pc.addTrack(track, stream);
  }
  pc.ontrack = (event) => {
    if (!remoteAudioNode) return;
    remoteAudioNode.srcObject = event.streams[0] ?? null;
    void remoteAudioNode.play().catch(() => {});
  };
  pc.onicecandidate = (event) => {
    if (!event.candidate || !activeCallPeer) return;
    void sendICECandidate(windowBase, { from: currentNumber, to: activeCallPeer, candidate: event.candidate.toJSON() });
  };
  pc.onconnectionstatechange = () => {
    if (syncCallRuntimeRef) syncCallRuntimeRef();
  };
  callPeer = pc;
  activeCallPeer = target;
  return pc;
}

async function handleSignalAction(action: string, payload: unknown): Promise<void> {
  const body = (payload ?? {}) as Record<string, unknown>;
  const from = String(body.from ?? '').trim();
  const to = String(body.to ?? '').trim();
  if (to && to !== currentNumber) return;

  if (action === 'ice_offer') {
    const offer = body.offer as RTCSessionDescriptionInit | undefined;
    if (!from || !offer) return;
    setCallPhase('ringing', `${from} から着信`);
    const pc = await ensurePeerForTarget(from);
    await pc.setRemoteDescription(new RTCSessionDescription(offer));
    // remoteDescriptionが設定されたのでバッファ済みcandidateを処理する
    const queued = pendingIceCandidates.splice(0);
    for (const c of queued) {
      await pc.addIceCandidate(new RTCIceCandidate(c)).catch(() => {});
    }
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    await sendICEAnswer(windowBase, { from: currentNumber, to: from, answer: pc.localDescription?.toJSON() ?? answer });
    setStatus('incoming offer accepted automatically');
    return;
  }

  if (action === 'ice_answer') {
    const answer = body.answer as RTCSessionDescriptionInit | undefined;
    if (!from || !answer || !callPeer) return;
    await callPeer.setRemoteDescription(new RTCSessionDescription(answer));
    // remoteDescriptionが設定されたのでバッファ済みcandidateを処理する
    const queued = pendingIceCandidates.splice(0);
    for (const c of queued) {
      await callPeer.addIceCandidate(new RTCIceCandidate(c)).catch(() => {});
    }
    const publicKeyHex = await getPublicKeyByNumber(windowBase, from);
    const challenge = createChallengeHex();
    pendingCallAuth = { peer: from, challenge, publicKeyHex };
    setCallPhase('verifying', `${from} の認証を検証中`);
    await sendCallAuthChallenge(windowBase, { from: currentNumber, to: from, challenge });
    setStatus('call auth challenge sent');
    return;
  }

  if (action === 'ice_candidate') {
    const candidate = body.candidate as RTCIceCandidateInit | undefined;
    if (!candidate) return;
    // peerConnectionが未作成またはremoteDescriptionが未設定ならキューに追加
    if (!callPeer || callPeer.remoteDescription === null) {
      pendingIceCandidates.push(candidate);
      return;
    }
    await callPeer.addIceCandidate(new RTCIceCandidate(candidate)).catch(() => {});
    return;
  }

  if (action === 'call_auth_challenge') {
    const challenge = String(body.challenge ?? '').trim();
    if (!from || !challenge) return;
    // セッション中の秘密鍵を使用する
    const privateKeyHex = currentPrivateKeyHex;
    if (!privateKeyHex) return;
    const sig = makeAuthSignatureHex(currentNumber, challenge, privateKeyHex);
    setCallPhase('verifying', `${from} に認証応答を送信`);
    await sendCallAuthResponse(windowBase, { from: currentNumber, to: from, challenge, sig });
    return;
  }

  if (action === 'call_auth_response') {
    const challenge = String(body.challenge ?? '').trim();
    const sig = String(body.sig ?? '').trim();
    if (!from || !challenge || !sig) return;
    if (!pendingCallAuth || pendingCallAuth.peer !== from || pendingCallAuth.challenge !== challenge) {
      await sendCallReject(windowBase, { from: currentNumber, to: from, reason: 'auth-state-mismatch' });
      cleanupCall();
      setCallPhase('ended', '認証状態不一致で通話終了');
      return;
    }
    const ok = verifyCallAuthSignature(from, challenge, sig, pendingCallAuth.publicKeyHex);
    pendingCallAuth = null;
    if (!ok) {
      await sendCallReject(windowBase, { from: currentNumber, to: from, reason: 'invalid-signature' });
      cleanupCall();
      setCallPhase('ended', '認証失敗で自動拒否');
      setStatus('call rejected automatically (auth failed)');
      return;
    }
    await sendCallAuthOK(windowBase, { from: currentNumber, to: from });
    setCallPhase('in_call', `${from} と通話中`);
    setStatus('call peer authentication passed');
    return;
  }

  if (action === 'call_auth_ok') {
    ringUser();
    setCallPhase('in_call', `${from} と通話中`);
    setStatus('authenticated incoming call');
    return;
  }

  if (action === 'call_reject') {
    cleanupCall();
    pendingCallAuth = null;
    setCallPhase('ended', `${from || '相手'} が拒否`);
    setStatus(`call rejected: ${String(body.reason ?? 'rejected')}`);
    return;
  }

  if (action === 'call_hangup') {
    cleanupCall();
    pendingCallAuth = null;
    setCallPhase('ended', `${from || '相手'} が終話`);
    setStatus('call hangup received');
  }
}

function normalizeRoutingNumber(route: string): string {
  const value = route.trim();
  if (!/^\d{2}$/.test(value)) {
    throw new Error('Routing Number は2桁（例: 02）で入力');
  }
  return value;
}

/** ニーモニックグリッドに24語を表示し、チェックボックスとボタンの連動も設定する */
function generateAndShowMnemonic(
  grid: HTMLElement,
  statusEl: HTMLElement,
  onKey: (hex: string) => void,
  confirmCheck: HTMLInputElement,
  submitBtn: HTMLButtonElement,
): void {
  grid.innerHTML = '';
  grid.dataset['mnemonic'] = '';
  statusEl.textContent = '生成中…';
  confirmCheck.checked = false;
  submitBtn.disabled = true;

  generateMnemonic().then(({ privateKeyHex, mnemonic }) => {
    onKey(privateKeyHex);
    grid.dataset['mnemonic'] = mnemonic;
    const words = mnemonic.split(' ');
    words.forEach((word, i) => {
      const cell = document.createElement('div');
      cell.style.cssText =
        'display:flex;align-items:center;gap:4px;padding:5px 8px;background:rgba(255,255,255,0.08);border-radius:8px;border:1px solid rgba(255,255,255,0.12);font-size:13px';
      const num = document.createElement('span');
      num.textContent = `${i + 1}.`;
      num.style.cssText = 'min-width:20px;font-size:11px;color:rgba(255,255,255,0.4);text-align:right';
      const wordSpan = document.createElement('span');
      wordSpan.textContent = word;
      wordSpan.style.cssText = 'font-family:monospace;font-weight:600;color:#e8e6ff';
      cell.appendChild(num);
      cell.appendChild(wordSpan);
      grid.appendChild(cell);
    });
    statusEl.textContent = '上の24語を必ず控えてください';
    statusEl.style.color = '#d9534f';
  }).catch((err: unknown) => {
    statusEl.textContent = `生成エラー: ${String(err)}`;
  });

  confirmCheck.onchange = () => {
    submitBtn.disabled = !confirmCheck.checked;
  };
}

export function buildUI(): void {
  const root = document.getElementById('app') ?? document.body;
  root.innerHTML = '';
  toastHostNode = document.createElement('div');
  toastHostNode.style.position = 'fixed';
  toastHostNode.style.top = '14px';
  toastHostNode.style.right = '14px';
  toastHostNode.style.zIndex = '9999';
  toastHostNode.style.display = 'flex';
  toastHostNode.style.flexDirection = 'column';
  toastHostNode.style.gap = '8px';
  toastHostNode.style.maxWidth = '340px';
  root.appendChild(toastHostNode);
  document.documentElement.style.height = '100%';
  document.body.style.height = '100%';
  document.body.style.margin = '0';
  document.body.style.background = '#13111c';
  document.body.style.overflowX = 'hidden';
  document.body.style.overflowY = 'auto';

  const container = document.createElement('div');
  container.style.width = '100%';
  container.style.minHeight = '100dvh';
  container.style.margin = '0';
  container.style.padding = '0';
  container.style.fontFamily = 'Noto Sans JP, Inter, sans-serif';
  container.style.boxSizing = 'border-box';
  container.style.display = 'flex';
  container.style.flexDirection = 'column';

  const h1 = document.createElement('h1');
  h1.textContent = 'SMS and Tell';
  h1.style.margin = '2px 0 4px 0';
  h1.style.fontSize = '24px';
  h1.style.color = '#2f3552';


  statusNode = document.createElement('div');
  statusNode.id = 'status';
  statusNode.textContent = 'ready';
  statusNode.style.padding = '8px 14px';
  statusNode.style.marginBottom = '12px';
  statusNode.style.background = 'rgba(108,99,255,0.1)';
  statusNode.style.border = '1px solid rgba(108,99,255,0.2)';
  statusNode.style.borderRadius = '12px';
  statusNode.style.color = 'rgba(200,196,255,0.9)';
  statusNode.style.fontSize = '12px';

  container.appendChild(h1);
  refreshAuthState();

  const nav = document.createElement('div');
  nav.style.display = 'flex';
  nav.style.gap = '0';
  nav.style.marginBottom = '0';
  nav.style.borderBottom = '1px solid #d8d4c7';

  let disconnectXButton: HTMLButtonElement | null = null;

  const syncAuthUI = (): void => {
    h1.style.display = isAuthenticated ? 'none' : 'block';
    if (statusNode) statusNode.style.display = isAuthenticated ? 'none' : 'block';
    if (disconnectXButton) {
      disconnectXButton.style.display = isAuthenticated ? 'inline-flex' : 'none';
    }
  };
  syncAuthUIRef = syncAuthUI;

  const screenHost = document.createElement('div');
  screenHost.style.flex = '1';
  screenHost.style.minHeight = '0';
  screenHost.style.display = 'flex';
  screenHost.style.flexDirection = 'column';

  const screens = {} as Record<ScreenKey, HTMLElement>;
  const navButtons: Partial<Record<ScreenKey, HTMLButtonElement>> = {};

  const makeNavButton = (key: ScreenKey, label: string): HTMLButtonElement => {
    const b = createButton(`tab-${key}`, label);
    b.style.margin = '0';
    b.style.borderRadius = '0';
    b.style.background = 'transparent';
    b.style.color = '#5b6075';
    b.style.border = 'none';
    b.style.padding = '12px 18px';
    b.style.fontSize = '13px';
    b.style.fontWeight = '700';
    b.style.borderBottom = '2px solid transparent';
    navButtons[key] = b;
    nav.appendChild(b);
    return b;
  };

  const setActiveScreen = (key: ScreenKey): void => {
    if (key === 'chat' && !isAuthenticated) {
      setStatus('ログイン認証が完了するまで会話画面へは進めません');
      return;
    }
    const targetKey: ScreenKey =
      isAuthenticated && key !== 'chat'
        ? 'chat'
        : key;
    activeScreenKey = targetKey;
    const keys: ScreenKey[] = ['login', 'signup', 'reset', 'chat'];
    for (const name of keys) {
      screens[name].style.display = name === targetKey ? (name !== 'chat' ? 'flex' : 'block') : 'none';
    }
    // サインアップ画面を開くときはステップ1に戻す
    if (targetKey === 'signup') {
      signupStep1.style.display = '';
      signupStep2.style.display = 'none';
      btnRegister.style.display = '';
      btnCreate.style.display = 'none';
    }
    // 再設定画面を開くときはステップ1に戻す
    if (targetKey === 'reset') {
      resetStep1.style.display = '';
      resetStep2.style.display = 'none';
      btnResetReq.style.display = '';
      btnResetDo.style.display = 'none';
    }
    syncAuthUI();
  };
  setActiveScreenRef = setActiveScreen;

  const initialWindowBase = localStorage.getItem(LS_WINDOW_BASE) ?? windowBase;
  windowBase = initialWindowBase;

  // --- カード型ヘルパー ---
  const makeCard = (title: string): HTMLDivElement => {
    const outerWrap = document.createElement('div');
    outerWrap.style.cssText =
      'width:100%;max-width:460px;position:relative;';
    outerWrap.dataset['role'] = 'auth-card-wrap';
    const card = document.createElement('div');
    card.style.cssText =
      'width:100%;padding:52px 48px 44px 48px;box-sizing:border-box;' +
      'background:rgba(255,255,255,0.06);' +
      'backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);' +
      'border:1px solid rgba(255,255,255,0.1);' +
      'border-radius:24px;' +
      'box-shadow:0 24px 64px rgba(0,0,0,0.5)';
    card.dataset['role'] = 'auth-card';
    const h2 = document.createElement('h2');
    h2.textContent = title;
    h2.style.textAlign = 'center';
    h2.style.marginBottom = '2rem';
    h2.style.fontSize = '24px';
    h2.style.fontWeight = '700';
    h2.style.color = '#fff';
    h2.style.letterSpacing = '-0.3px';
    card.appendChild(h2);
    outerWrap.appendChild(card);
    (card as unknown as { __outerWrap?: HTMLElement }).__outerWrap = outerWrap;
    return card;
  };

  const makeFormGroup = (label: string, input: HTMLInputElement): HTMLDivElement => {
    const group = document.createElement('div');
    group.style.marginBottom = '1.2rem';
    const lbl = document.createElement('label');
    lbl.textContent = label;
    lbl.style.display = 'block';
    lbl.style.marginBottom = '0.4rem';
    lbl.style.fontWeight = '600';
    lbl.style.fontSize = '12px';
    lbl.style.color = '#aaa';
    lbl.style.textTransform = 'uppercase';
    input.style.width = '100%';
    input.style.padding = '15px 20px';
    input.style.border = 'none';
    input.style.borderRadius = '25px';
    input.style.fontSize = '14px';
    input.style.boxSizing = 'border-box';
    input.style.background = 'rgba(255,255,255,.1)';
    input.style.color = '#fff';
    input.style.outline = 'none';
    input.addEventListener('focus', () => { input.style.background = 'rgba(255,255,255,.18)'; });
    input.addEventListener('blur', () => { input.style.background = 'rgba(255,255,255,.1)'; });
    group.appendChild(lbl);
    group.appendChild(input);
    return group;
  };

  const makePrimaryBtn = (id: string, label: string): HTMLButtonElement => {
    const btn = createButton(id, label);
    btn.style.width = '100%';
    btn.style.padding = '14px 20px';
    btn.style.background = 'linear-gradient(135deg, #6c63ff 0%, #4f8ef7 100%)';
    btn.style.color = '#ffffff';
    btn.style.border = 'none';
    btn.style.borderRadius = '14px';
    btn.style.fontSize = '15px';
    btn.style.fontWeight = '700';
    btn.style.cursor = 'pointer';
    btn.style.marginBottom = '0';
    btn.style.marginRight = '0';
    btn.style.letterSpacing = '0.3px';
    btn.style.boxShadow = '0 4px 18px rgba(108,99,255,0.4)';
    return btn;
  };

  const makeLinkBtn = (label: string, onClick: () => void): HTMLButtonElement => {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.textContent = label;
    btn.style.display = 'block';
    btn.style.width = '100%';
    btn.style.textAlign = 'center';
    btn.style.marginTop = '1rem';
    btn.style.border = 'none';
    btn.style.background = 'transparent';
    btn.style.color = 'rgba(255,255,255,.6)';
    btn.style.cursor = 'pointer';
    btn.style.fontSize = '13px';
    btn.onclick = onClick;
    return btn;
  };

  // --- ログイン画面 ---
  const loginScreen = document.createElement('div');
  loginScreen.style.cssText = 'width:100%;background:linear-gradient(135deg,#13111c 0%,#1d1b31 50%,#111827 100%);display:flex;justify-content:center;align-items:center;padding:40px 16px;box-sizing:border-box;min-height:100%';
  const loginCard = makeCard('ログイン');

  const numberInput = createInput('number', '番号 (例: 02-xxxxxxxx)', localStorage.getItem(LS_PHONE_NUMBER) ?? localStorage.getItem(LS_NUMBER) ?? '');
  const privateKeyInput = createInput('privateKey', '秘密鍵 (hex)');
  privateKeyInput.type = 'password';
  privateKeyInput.autocomplete = 'off';
  let privateKeyMaskTimer: number | null = null;

  // --- メインセクション: 番号 + ニーモニック ---
  loginCard.appendChild(makeFormGroup('番号', numberInput));

  // ニーモニック入力（メイン）
  const mnemonicLoginGroup = document.createElement('div');
  mnemonicLoginGroup.style.marginBottom = '1.2rem';
  const mnemonicLoginLabel = document.createElement('label');
  mnemonicLoginLabel.textContent = 'ニーモニック';
  mnemonicLoginLabel.style.cssText = 'display:block;margin-bottom:0.4rem;font-weight:600;font-size:12px;color:#aaa;text-transform:uppercase';
  const mnemonicLoginTextarea = document.createElement('textarea');
  mnemonicLoginTextarea.id = 'mnemonicLogin';
  mnemonicLoginTextarea.placeholder = '24語のニーモニックをスペース区切りで入力…';
  mnemonicLoginTextarea.rows = 3;
  mnemonicLoginTextarea.style.cssText = 'width:100%;box-sizing:border-box;border:none;border-radius:15px;padding:12px 16px;font-size:13px;font-family:monospace;resize:vertical;background:rgba(255,255,255,.1);color:#fff;outline:none';
  mnemonicLoginTextarea.addEventListener('focus', () => { mnemonicLoginTextarea.style.background = 'rgba(255,255,255,.18)'; });
  mnemonicLoginTextarea.addEventListener('blur', () => { mnemonicLoginTextarea.style.background = 'rgba(255,255,255,.1)'; });
  mnemonicLoginGroup.appendChild(mnemonicLoginLabel);
  mnemonicLoginGroup.appendChild(mnemonicLoginTextarea);
  loginCard.appendChild(mnemonicLoginGroup);

  // 端末に保存
  const persistSensitiveLabel = document.createElement('label');
  persistSensitiveLabel.style.display = 'inline-flex';
  persistSensitiveLabel.style.alignItems = 'center';
  persistSensitiveLabel.style.gap = '6px';
  persistSensitiveLabel.style.fontSize = '12px';
  persistSensitiveLabel.style.color = 'rgba(255,255,255,.7)';
  persistSensitiveLabel.style.marginBottom = '0.6rem';
  const persistSensitiveCheck = document.createElement('input');
  persistSensitiveCheck.type = 'checkbox';
  persistSensitiveCheck.checked = (localStorage.getItem(LS_PERSIST_SENSITIVE) ?? '1') !== '0';
  const persistSensitiveText = document.createElement('span');
  persistSensitiveText.textContent = '端末に保存';
  persistSensitiveLabel.appendChild(persistSensitiveCheck);
  persistSensitiveLabel.appendChild(persistSensitiveText);
  loginCard.appendChild(persistSensitiveLabel);

  // 保存用パスワード（端末に保存チェック時のみ表示）
  const savePasswordInput = createInput('savePassword', 'パスワード（保存・復元に使用）');
  savePasswordInput.type = 'password';
  savePasswordInput.autocomplete = 'new-password';
  const savePasswordGroup = makeFormGroup('保存パスワード', savePasswordInput);
  savePasswordGroup.style.marginBottom = '1.2rem';
  const hasSavedEncryptedKey = !!localStorage.getItem(LS_ENCRYPTED_KEY);
  savePasswordGroup.style.display = (persistSensitiveCheck.checked || hasSavedEncryptedKey) ? 'block' : 'none';
  loginCard.appendChild(savePasswordGroup);
  persistSensitiveCheck.addEventListener('change', () => {
    savePasswordGroup.style.display = persistSensitiveCheck.checked ? 'block' : 'none';
  });

  const btnLookupConnect = makePrimaryBtn('btnLookupConnect', 'ログイン');
  loginCard.appendChild(btnLookupConnect);

  // HR 区切り線
  const loginHr = document.createElement('div');
  loginHr.style.cssText = 'height:2px;margin:30px 0 20px 0;background:rgba(255,255,255,.2)';
  loginCard.appendChild(loginHr);

  // --- サブセクション: 秘密鍵で直接ログイン（折りたたみ）---
  const privateKeyToggle = document.createElement('button');
  privateKeyToggle.type = 'button';
  privateKeyToggle.textContent = '▶ 秘密鍵で直接ログインする';
  privateKeyToggle.style.cssText = 'border:none;background:transparent;color:rgba(255,255,255,.7);cursor:pointer;font-size:13px;padding:0;margin-bottom:0.5rem;text-align:left;width:100%';

  const privateKeySection = document.createElement('div');
  privateKeySection.style.display = 'none';
  privateKeySection.style.marginBottom = '1rem';

  privateKeySection.appendChild(makeFormGroup('秘密鍵', privateKeyInput));

  const privateKeyControl = document.createElement('div');
  privateKeyControl.style.marginBottom = '1rem';
  privateKeyControl.style.display = 'flex';
  privateKeyControl.style.alignItems = 'center';
  privateKeyControl.style.gap = '10px';

  const btnTogglePrivateKey = document.createElement('button');
  btnTogglePrivateKey.type = 'button';
  btnTogglePrivateKey.textContent = '秘密鍵を表示';
  btnTogglePrivateKey.style.border = 'none';
  btnTogglePrivateKey.style.background = 'transparent';
  btnTogglePrivateKey.style.color = 'rgba(255,255,255,.7)';
  btnTogglePrivateKey.style.cursor = 'pointer';
  btnTogglePrivateKey.style.fontSize = '13px';
  btnTogglePrivateKey.style.padding = '0';
  btnTogglePrivateKey.onclick = () => {
    const isHidden = privateKeyInput.type === 'password';
    privateKeyInput.type = isHidden ? 'text' : 'password';
    btnTogglePrivateKey.textContent = isHidden ? '秘密鍵を隠す' : '秘密鍵を表示';
  };
  privateKeyInput.addEventListener('paste', () => {
    if (privateKeyMaskTimer) clearTimeout(privateKeyMaskTimer);
    privateKeyInput.type = 'text';
    btnTogglePrivateKey.textContent = '秘密鍵を隠す';
    privateKeyMaskTimer = window.setTimeout(() => {
      privateKeyInput.type = 'password';
      btnTogglePrivateKey.textContent = '秘密鍵を表示';
    }, 5000);
  });
  privateKeyControl.appendChild(btnTogglePrivateKey);
  privateKeySection.appendChild(privateKeyControl);

  privateKeyToggle.onclick = () => {
    const shown = privateKeySection.style.display !== 'none';
    privateKeySection.style.display = shown ? 'none' : 'block';
    privateKeyToggle.textContent = shown
      ? '▶ 秘密鍵で直接ログインする'
      : '▼ 秘密鍵で直接ログインする';
  };
  loginCard.appendChild(privateKeyToggle);
  loginCard.appendChild(privateKeySection);

  loginCard.appendChild(makeLinkBtn('新規登録はこちら', () => setActiveScreen('signup')));
  loginCard.appendChild(makeLinkBtn('パスワードを忘れた方', () => setActiveScreen('reset')));
  loginScreen.appendChild((loginCard as unknown as { __outerWrap?: HTMLElement }).__outerWrap ?? loginCard);

  // --- 新規登録画面 ---
  const signupScreen = document.createElement('div');
  signupScreen.style.cssText = 'width:100%;background:linear-gradient(135deg,#13111c 0%,#1d1b31 50%,#111827 100%);display:flex;justify-content:center;align-items:center;padding:40px 16px;box-sizing:border-box;min-height:100%';
  const signupCard = makeCard('新規登録');

  const signupRouteInput = createInput('signupRoute', 'ルーティング番号（2桁、例: 02）');
  const signupEmailInput = createInput('signupEmail', 'メールアドレス');
  const signupTokenInput = createInput('signupToken', 'メールのトークン');

  // 生成した秘密鍵を一時保存（入力フィールドには出さない）
  let signupGeneratedKeyHex = '';

  const signupStep1 = document.createElement('div');
  const signupStep2 = document.createElement('div');
  signupStep2.style.display = 'none';

  signupStep1.appendChild(makeFormGroup('ルーティング番号', signupRouteInput));
  signupStep1.appendChild(makeFormGroup('メールアドレス', signupEmailInput));

  // Step2 – ニーモニック表示 UI
  const signupStep2Note = document.createElement('p');
  signupStep2Note.innerHTML =
    '新しい秘密鍵を自動生成しました。<br>' +
    '<strong>以下の24語のニーモニックを紙などに控えてください。</strong><br>' +
    'このニーモニックがないと秘密鍵を復元できません。';
  signupStep2Note.style.cssText = 'margin:0 0 0.8rem 0;font-size:13px;color:#ddd;line-height:1.5';
  signupStep2.appendChild(signupStep2Note);
  signupStep2.appendChild(makeFormGroup('トークン', signupTokenInput));

  // ニーモニック表示グリッド
  const signupMnemonicGrid = document.createElement('div');
  signupMnemonicGrid.style.cssText =
    'display:grid;grid-template-columns:repeat(3,1fr);gap:4px;margin:0 0 0.6rem 0;background:rgba(255,255,255,0.05);border-radius:14px;padding:12px;border:1px solid rgba(255,255,255,0.08)';
  const signupMnemonicStatus = document.createElement('p');
  signupMnemonicStatus.textContent = '生成中…';
  signupMnemonicStatus.style.cssText = 'font-size:12px;color:rgba(255,255,255,.6);margin:0 0 0.5rem 0;text-align:center';
  signupStep2.appendChild(signupMnemonicGrid);
  signupStep2.appendChild(signupMnemonicStatus);

  // コピーボタン
  const btnSignupCopyMnemonic = document.createElement('button');
  btnSignupCopyMnemonic.type = 'button';
  btnSignupCopyMnemonic.textContent = 'ニーモニックをコピー';
  btnSignupCopyMnemonic.style.cssText =
    'border:1px solid rgba(255,255,255,.5);background:transparent;color:rgba(255,255,255,.8);border-radius:25px;padding:6px 14px;cursor:pointer;font-size:13px;margin-right:8px';
  btnSignupCopyMnemonic.onclick = () => {
    navigator.clipboard.writeText(signupMnemonicGrid.dataset['mnemonic'] ?? '').then(() => {
      btnSignupCopyMnemonic.textContent = 'コピー済み ✓';
      setTimeout(() => { btnSignupCopyMnemonic.textContent = 'ニーモニックをコピー'; }, 2000);
    });
  };

  // 再生成ボタン
  const btnSignupRegen = document.createElement('button');
  btnSignupRegen.type = 'button';
  btnSignupRegen.textContent = '再生成';
  btnSignupRegen.style.cssText =
    'border:1px solid rgba(255,255,255,.3);background:transparent;color:rgba(255,255,255,.6);border-radius:25px;padding:6px 14px;cursor:pointer;font-size:13px';
  btnSignupRegen.onclick = () => {
    generateAndShowMnemonic(
      signupMnemonicGrid, signupMnemonicStatus,
      (hex) => { signupGeneratedKeyHex = hex; },
      signupConfirmCheck, btnCreate,
    );
  };

  const signupBtnRow = document.createElement('div');
  signupBtnRow.style.cssText = 'display:flex;gap:8px;margin-bottom:0.8rem';
  signupBtnRow.appendChild(btnSignupCopyMnemonic);
  signupBtnRow.appendChild(btnSignupRegen);
  signupStep2.appendChild(signupBtnRow);

  // 確認チェックボックス
  const signupConfirmLabel = document.createElement('label');
  signupConfirmLabel.style.cssText = 'display:flex;align-items:flex-start;gap:6px;font-size:13px;color:#ddd;margin-bottom:1rem;cursor:pointer';
  const signupConfirmCheck = document.createElement('input');
  signupConfirmCheck.type = 'checkbox';
  signupConfirmCheck.style.marginTop = '2px';
  const signupConfirmText = document.createElement('span');
  signupConfirmText.textContent = 'ニーモニックを安全な場所に控えました（このニーモニックが唯一のバックアップです）';
  signupConfirmLabel.appendChild(signupConfirmCheck);
  signupConfirmLabel.appendChild(signupConfirmText);
  signupStep2.appendChild(signupConfirmLabel);

  signupCard.appendChild(signupStep1);
  signupCard.appendChild(signupStep2);

  const btnRegister = makePrimaryBtn('btnRegisterEmail', '確認メール送信');
  const btnCreate = makePrimaryBtn('btnCreateAccount', 'アカウント作成');
  btnCreate.style.display = 'none';
  const signupButtonWrap = document.createElement('div');
  signupButtonWrap.style.display = 'flex';
  signupButtonWrap.style.flexDirection = 'column';
  signupButtonWrap.style.gap = '8px';
  signupButtonWrap.appendChild(btnRegister);
  signupButtonWrap.appendChild(btnCreate);
  signupCard.appendChild(signupButtonWrap);
  signupCard.appendChild(makeLinkBtn('すでにアカウントをお持ちの方', () => setActiveScreen('login')));
  signupScreen.appendChild((signupCard as unknown as { __outerWrap?: HTMLElement }).__outerWrap ?? signupCard);

  // --- 再設定画面 ---
  const resetScreen = document.createElement('div');
  resetScreen.style.cssText = 'width:100%;background:linear-gradient(135deg,#13111c 0%,#1d1b31 50%,#111827 100%);display:flex;justify-content:center;align-items:center;padding:40px 16px;box-sizing:border-box;min-height:100%';
  const resetCard = makeCard('秘密鍵の再設定');

  const resetRouteInput = createInput('resetRoute', 'ルーティング番号（2桁、例: 02）');
  const resetEmailInput = createInput('resetEmail', 'メールアドレス');
  const resetTokenInput = createInput('resetToken', '再設定トークン');

  // 生成した新しい秘密鍵を一時保存
  let resetGeneratedKeyHex = '';

  const resetStep1 = document.createElement('div');
  const resetStep2 = document.createElement('div');
  resetStep2.style.display = 'none';

  resetStep1.appendChild(makeFormGroup('ルーティング番号', resetRouteInput));
  resetStep1.appendChild(makeFormGroup('メールアドレス', resetEmailInput));

  // Step2 – ニーモニック表示 UI
  const resetStep2Note = document.createElement('p');
  resetStep2Note.innerHTML =
    '新しい秘密鍵を自動生成しました。<br>' +
    '<strong>以下の24語のニーモニックを紙などに控えてください。</strong><br>' +
    'このニーモニックがないと秘密鍵を復元できません。';
  resetStep2Note.style.cssText = 'margin:0 0 0.8rem 0;font-size:13px;color:#ddd;line-height:1.5';
  resetStep2.appendChild(resetStep2Note);
  resetStep2.appendChild(makeFormGroup('トークン', resetTokenInput));

  const resetMnemonicGrid = document.createElement('div');
  resetMnemonicGrid.style.cssText =
    'display:grid;grid-template-columns:repeat(3,1fr);gap:4px;margin:0 0 0.6rem 0;background:rgba(255,255,255,0.05);border-radius:14px;padding:12px;border:1px solid rgba(255,255,255,0.08)';
  const resetMnemonicStatus = document.createElement('p');
  resetMnemonicStatus.textContent = '生成中…';
  resetMnemonicStatus.style.cssText = 'font-size:12px;color:rgba(255,255,255,.6);margin:0 0 0.5rem 0;text-align:center';
  resetStep2.appendChild(resetMnemonicGrid);
  resetStep2.appendChild(resetMnemonicStatus);

  const btnResetCopyMnemonic = document.createElement('button');
  btnResetCopyMnemonic.type = 'button';
  btnResetCopyMnemonic.textContent = 'ニーモニックをコピー';
  btnResetCopyMnemonic.style.cssText =
    'border:1px solid rgba(255,255,255,.5);background:transparent;color:rgba(255,255,255,.8);border-radius:25px;padding:6px 14px;cursor:pointer;font-size:13px;margin-right:8px';
  btnResetCopyMnemonic.onclick = () => {
    navigator.clipboard.writeText(resetMnemonicGrid.dataset['mnemonic'] ?? '').then(() => {
      btnResetCopyMnemonic.textContent = 'コピー済み ✓';
      setTimeout(() => { btnResetCopyMnemonic.textContent = 'ニーモニックをコピー'; }, 2000);
    });
  };

  const btnResetRegen = document.createElement('button');
  btnResetRegen.type = 'button';
  btnResetRegen.textContent = '再生成';
  btnResetRegen.style.cssText =
    'border:1px solid rgba(255,255,255,.3);background:transparent;color:rgba(255,255,255,.6);border-radius:25px;padding:6px 14px;cursor:pointer;font-size:13px';
  btnResetRegen.onclick = () => {
    generateAndShowMnemonic(
      resetMnemonicGrid, resetMnemonicStatus,
      (hex) => { resetGeneratedKeyHex = hex; },
      resetConfirmCheck, btnResetDo,
    );
  };

  const resetBtnRow = document.createElement('div');
  resetBtnRow.style.cssText = 'display:flex;gap:8px;margin-bottom:0.8rem';
  resetBtnRow.appendChild(btnResetCopyMnemonic);
  resetBtnRow.appendChild(btnResetRegen);
  resetStep2.appendChild(resetBtnRow);

  const syncResponsiveUI = (): void => {
    const isNarrow = window.innerWidth < 640;

    for (const screen of [loginScreen, signupScreen, resetScreen]) {
      screen.style.alignItems = isNarrow ? 'flex-start' : 'center';
      screen.style.padding = isNarrow ? '20px 12px 24px 12px' : '40px 16px';
    }

    for (const card of [loginCard, signupCard, resetCard]) {
      card.style.padding = isNarrow ? '28px 20px 24px 20px' : '52px 48px 44px 48px';
      card.style.borderRadius = isNarrow ? '18px' : '24px';
    }

    signupMnemonicGrid.style.gridTemplateColumns = isNarrow ? 'repeat(2,minmax(0,1fr))' : 'repeat(3,minmax(0,1fr))';
    resetMnemonicGrid.style.gridTemplateColumns = isNarrow ? 'repeat(2,minmax(0,1fr))' : 'repeat(3,minmax(0,1fr))';

    for (const row of [signupBtnRow, resetBtnRow]) {
      row.style.flexWrap = isNarrow ? 'wrap' : 'nowrap';
    }
    for (const btn of [btnSignupCopyMnemonic, btnSignupRegen, btnResetCopyMnemonic, btnResetRegen]) {
      btn.style.flex = isNarrow ? '1 1 calc(50% - 4px)' : '0 0 auto';
    }

    privateKeyControl.style.flexWrap = isNarrow ? 'wrap' : 'nowrap';
    if (toastHostNode) {
      toastHostNode.style.left = isNarrow ? '12px' : '';
      toastHostNode.style.right = isNarrow ? '12px' : '14px';
      toastHostNode.style.maxWidth = isNarrow ? 'none' : '340px';
    }
  };

  syncResponsiveUI();
  window.addEventListener('resize', syncResponsiveUI);

  const resetConfirmLabel = document.createElement('label');
  resetConfirmLabel.style.cssText = 'display:flex;align-items:flex-start;gap:6px;font-size:13px;color:#ddd;margin-bottom:1rem;cursor:pointer';
  const resetConfirmCheck = document.createElement('input');
  resetConfirmCheck.type = 'checkbox';
  resetConfirmCheck.style.marginTop = '2px';
  const resetConfirmText = document.createElement('span');
  resetConfirmText.textContent = 'ニーモニックを安全な場所に控えました（このニーモニックが唯一のバックアップです）';
  resetConfirmLabel.appendChild(resetConfirmCheck);
  resetConfirmLabel.appendChild(resetConfirmText);
  resetStep2.appendChild(resetConfirmLabel);

  resetCard.appendChild(resetStep1);
  resetCard.appendChild(resetStep2);

  const btnResetReq = makePrimaryBtn('btnResetRequest', '再設定メール送信');
  const btnResetDo = makePrimaryBtn('btnResetDo', '再設定を実行');
  btnResetDo.style.display = 'none';
  const resetButtonWrap = document.createElement('div');
  resetButtonWrap.style.display = 'flex';
  resetButtonWrap.style.flexDirection = 'column';
  resetButtonWrap.style.gap = '8px';
  resetButtonWrap.appendChild(btnResetReq);
  resetButtonWrap.appendChild(btnResetDo);
  resetCard.appendChild(resetButtonWrap);
  resetCard.appendChild(makeLinkBtn('ログインに戻る', () => setActiveScreen('login')));
  resetScreen.appendChild((resetCard as unknown as { __outerWrap?: HTMLElement }).__outerWrap ?? resetCard);

  const chatScreen = createSection('会話画面');
  chatScreen.style.background = 'transparent';
  chatScreen.style.border = 'none';
  chatScreen.style.padding = '0';
  chatScreen.style.marginBottom = '0';
  const chatScreenTitle = chatScreen.querySelector('h3');
  if (chatScreenTitle) {
    chatScreenTitle.style.display = 'none';
  }
  const smsToInput = createInput('smsTo', 'to number');
  const smsFromInput = createInput('smsFrom', 'from number');
  const smsSigInput = createInput('smsSig', 'signature hex');
  const smsBody = document.createElement('textarea');
  smsBody.id = 'smsBody';
  smsBody.placeholder = 'メッセージ';
  smsBody.style.minHeight = '40px';
  smsBody.style.maxHeight = '100px';
  smsBody.style.border = 'none';
  smsBody.style.background = 'transparent';
  smsBody.style.resize = 'none';
  smsBody.style.outline = 'none';
  styleInputBase(smsBody);

  const chatShell = document.createElement('div');
  chatShell.style.display = 'grid';
  chatShell.style.gridTemplateColumns = '300px 1fr';
  chatShell.style.gap = '0';
  chatShell.style.marginTop = '0';
  chatShell.style.height = '100dvh';
  chatShell.style.minHeight = '0';

  const threadsPane = document.createElement('div');
  threadsPane.style.background = '#ffffff';
  threadsPane.style.border = 'none';
  threadsPane.style.borderRight = '1px solid #eef0f8';
  threadsPane.style.borderRadius = '0';
  threadsPane.style.padding = '0';
  threadsPane.style.minHeight = '0';
  threadsPane.style.height = '100%';
  threadsPane.style.display = 'flex';
  threadsPane.style.flexDirection = 'column';

  const conversationPane = document.createElement('div');
  conversationPane.style.background = '#f5f7ff';
  conversationPane.style.border = 'none';
  conversationPane.style.borderRadius = '0';
  conversationPane.style.padding = '0';
  conversationPane.style.minHeight = '0';
  conversationPane.style.height = '100%';
  conversationPane.style.display = 'flex';
  conversationPane.style.flexDirection = 'column';
  conversationPane.style.gap = '0';

  let isMobileChatLayout = false;
  let mobileChatPane: 'threads' | 'conversation' = 'threads';
  let mobileBackButton: HTMLButtonElement | null = null;
  let peerNameField: HTMLInputElement | null = null;
  let mobileOpenConversationButton: HTMLButtonElement | null = null;

  const syncPaneVisibility = (): void => {
    if (!isMobileChatLayout) {
      threadsPane.style.display = 'block';
      conversationPane.style.display = 'flex';
  conversationPane.style.flexDirection = 'column';
      return;
    }
    if (mobileChatPane === 'threads') {
      threadsPane.style.display = 'block';
      conversationPane.style.display = 'none';
    } else {
      threadsPane.style.display = 'none';
      conversationPane.style.display = 'flex';
  conversationPane.style.flexDirection = 'column';
    }
  };

  const syncChatLayout = (): void => {
    const narrow = window.innerWidth < 640;
    if (window.innerWidth < 900) {
      isMobileChatLayout = true;
      chatShell.style.gridTemplateColumns = '1fr';
      chatShell.style.gap = '0';
      chatShell.style.height = '100dvh';
      threadsPane.style.height = '100%';
      conversationPane.style.height = '100%';
    } else {
      isMobileChatLayout = false;
      chatShell.style.gridTemplateColumns = '300px 1fr';
      chatShell.style.gap = '0';
      chatShell.style.height = '100dvh';
      threadsPane.style.height = '100%';
      conversationPane.style.height = '100%';
    }
    chatTopBar.style.padding = narrow ? '8px 10px' : '10px 14px';
    chatTopBar.style.gap = narrow ? '8px' : '10px';
    composerWrap.style.padding = narrow ? '8px 10px' : '10px 14px';
    peerNameInput.style.maxWidth = narrow ? '130px' : '220px';
    smsBody.style.fontSize = narrow ? '16px' : '14px';
    syncPaneVisibility();
    if (mobileBackButton) mobileBackButton.style.display = isMobileChatLayout ? '' : 'none';
    if (peerNameField) peerNameField.style.display = isMobileChatLayout ? 'none' : '';
    if (mobileOpenConversationButton) mobileOpenConversationButton.style.display = isMobileChatLayout ? '' : 'none';
  };

  chatShell.appendChild(threadsPane);
  chatShell.appendChild(conversationPane);
  chatScreen.appendChild(chatShell);

  const chatHeader = document.createElement('div');
  chatHeader.style.display = 'grid';
  chatHeader.style.gap = '8px';
  chatHeader.style.marginBottom = '0';
  chatHeader.style.padding = '12px 14px';
  chatHeader.style.borderBottom = '1px solid #eef0f8';

  const threadHeaderRow = document.createElement('div');
  threadHeaderRow.style.display = 'flex';
  threadHeaderRow.style.alignItems = 'center';
  threadHeaderRow.style.justifyContent = 'space-between';
  threadHeaderRow.style.gap = '8px';

  const threadHeaderTitle = document.createElement('div');
  threadHeaderTitle.textContent = 'メッセージ';
  threadHeaderTitle.style.fontSize = '14px';
  threadHeaderTitle.style.fontWeight = '700';
  threadHeaderTitle.style.color = '#1a1a2e';

  const btnCreateThread = document.createElement('button');
  btnCreateThread.type = 'button';
  btnCreateThread.textContent = '+';
  btnCreateThread.title = '新規作成';
  btnCreateThread.style.width = '30px';
  btnCreateThread.style.height = '30px';
  btnCreateThread.style.borderRadius = '999px';
  btnCreateThread.style.border = 'none';
  btnCreateThread.style.background = 'linear-gradient(135deg,#6c63ff,#4f8ef7)';
  btnCreateThread.style.color = '#ffffff';
  btnCreateThread.style.fontSize = '18px';
  btnCreateThread.style.lineHeight = '1';
  btnCreateThread.style.cursor = 'pointer';
  btnCreateThread.style.boxShadow = '0 2px 8px rgba(108,99,255,0.35)';

  threadHeaderRow.appendChild(threadHeaderTitle);
  threadHeaderRow.appendChild(btnCreateThread);
  chatHeader.appendChild(threadHeaderRow);

  const btnOpenConversation = createButton('btnOpenConversation', '会話を開く');
  btnOpenConversation.style.width = '100%';
  btnOpenConversation.style.display = 'none';
  mobileOpenConversationButton = btnOpenConversation;
  chatHeader.appendChild(btnOpenConversation);
  threadsPane.appendChild(chatHeader);

  const chatTopBar = document.createElement('div');
  chatTopBar.style.display = 'flex';
  chatTopBar.style.alignItems = 'center';
  chatTopBar.style.gap = '10px';
  chatTopBar.style.padding = '10px 14px';
  chatTopBar.style.background = '#ffffff';
  chatTopBar.style.border = 'none';
  chatTopBar.style.borderBottom = '1px solid #eef0f8';
  chatTopBar.style.borderRadius = '0';
  chatTopBar.style.marginBottom = '0';

  const avatar = document.createElement('div');
  avatar.textContent = '●';
  avatar.style.width = '32px';
  avatar.style.height = '32px';
  avatar.style.borderRadius = '999px';
  avatar.style.display = 'grid';
  avatar.style.placeItems = 'center';
  avatar.style.background = 'linear-gradient(135deg,#6c63ff,#4f8ef7)';
  avatar.style.color = '#ffffff';
  avatar.style.fontSize = '10px';
  avatar.style.flexShrink = '0';

  const chatPeerLabel = document.createElement('div');
  chatPeerLabel.style.fontSize = '14px';
  chatPeerLabel.style.fontWeight = '700';
  chatPeerLabel.style.color = '#1a1a2e';
  chatPeerLabel.textContent = '宛先未設定';

  const peerNameInput = createInput('peerName', '番号の表示名');
  peerNameInput.style.maxWidth = '220px';
  peerNameInput.style.marginLeft = 'auto';

  const btnHeaderCall = createButton('btnHeaderCall', '📞');
  btnHeaderCall.style.marginRight = '0';
  btnHeaderCall.style.marginBottom = '0';
  btnHeaderCall.style.borderRadius = '12px';
  btnHeaderCall.style.padding = '6px 12px';
  btnHeaderCall.style.background = 'linear-gradient(135deg,#6c63ff,#4f8ef7)';
  btnHeaderCall.style.color = '#ffffff';
  btnHeaderCall.style.border = 'none';
  btnHeaderCall.style.boxShadow = '0 2px 8px rgba(108,99,255,0.3)';

  const btnMobileBack = createButton('btnMobileBack', '←');
  btnMobileBack.style.marginRight = '0';
  btnMobileBack.style.marginBottom = '0';
  btnMobileBack.style.padding = '6px 10px';
  btnMobileBack.style.display = 'none';
  mobileBackButton = btnMobileBack;
  peerNameField = peerNameInput;

  chatTopBar.appendChild(btnMobileBack);
  chatTopBar.appendChild(avatar);
  chatTopBar.appendChild(chatPeerLabel);
  chatTopBar.appendChild(btnHeaderCall);
  chatTopBar.appendChild(peerNameInput);
  conversationPane.appendChild(chatTopBar);

  const callHost = document.createElement('div');
  callHost.style.marginTop = '6px';
  callHost.style.display = 'none';
  conversationPane.appendChild(callHost);

  const composerWrap = document.createElement('div');
  composerWrap.style.display = 'grid';
  composerWrap.style.gridTemplateColumns = '1fr auto';
  composerWrap.style.gap = '8px';
  composerWrap.style.alignItems = 'end';
  composerWrap.style.marginTop = '0';
  composerWrap.style.padding = '10px 14px';
  composerWrap.style.background = '#ffffff';
  composerWrap.style.border = 'none';
  composerWrap.style.borderTop = '1px solid #eef0f8';
  composerWrap.style.borderRadius = '0';
  composerWrap.style.position = 'sticky';
  composerWrap.style.bottom = '0';

  const btnSendSMS = createButton('btnSendSMS', '↑');
  btnSendSMS.style.marginRight = '0';
  btnSendSMS.style.marginBottom = '0';
  btnSendSMS.style.background = 'linear-gradient(135deg,#6c63ff,#4f8ef7)';
  btnSendSMS.style.color = '#ffffff';
  btnSendSMS.style.border = 'none';
  btnSendSMS.style.borderRadius = '999px';
  btnSendSMS.style.width = '38px';
  btnSendSMS.style.height = '38px';
  btnSendSMS.style.padding = '0';
  btnSendSMS.style.fontSize = '18px';
  btnSendSMS.style.boxShadow = '0 2px 8px rgba(108,99,255,0.4)';

  const sendHistoryTitle = document.createElement('h3');
  sendHistoryTitle.textContent = '';
  sendHistoryTitle.style.marginTop = '4px';
  sendHistoryTitle.style.display = 'none';
  threadsPane.appendChild(sendHistoryTitle);

  threadListNode = document.createElement('div');
  threadListNode.style.display = 'flex';
  threadListNode.style.flexDirection = 'column';
  threadListNode.style.gap = '0';
  threadListNode.style.flex = '1';
  threadListNode.style.minHeight = '0';
  threadListNode.style.overflowY = 'auto';
  threadsPane.appendChild(threadListNode);

  messageFeedNode = document.createElement('div');
  messageFeedNode.style.display = 'flex';
  messageFeedNode.style.flexDirection = 'column';
  messageFeedNode.style.gap = '6px';
  messageFeedNode.style.overflowY = 'auto';
  messageFeedNode.style.padding = '10px 14px';
  messageFeedNode.style.border = 'none';
  messageFeedNode.style.borderRadius = '0';
  messageFeedNode.style.background = '#f5f7ff';
  messageFeedNode.style.minHeight = '0';
  messageFeedNode.style.flex = '1';
  conversationPane.appendChild(messageFeedNode);

  btnOpenConversation.onclick = () => {
    const to = smsToInput.value.trim();
    if (!to) {
      startComposeThread();
      return;
    }
    activeThreadNumber = to;
    mobileChatPane = 'conversation';
    syncPaneVisibility();
  };

  btnMobileBack.onclick = () => {
    mobileChatPane = 'threads';
    syncPaneVisibility();
  };

  peerNameInput.addEventListener('change', () => {
    const to = smsToInput.value.trim();
    if (!to) return;
    const name = peerNameInput.value.trim();
    if (name) {
      contactNames[to] = name;
    } else {
      delete contactNames[to];
    }
    chatPeerLabel.textContent = getDisplayName(to);
    renderThreadList();
    persistThread();
  });

  composerWrap.appendChild(smsBody);
  composerWrap.appendChild(btnSendSMS);
  conversationPane.appendChild(composerWrap);

  syncChatLayout();
  window.addEventListener('resize', syncChatLayout);

  const callTitle = document.createElement('h3');
  callTitle.textContent = '電話（シグナリング）';
  callTitle.style.margin = '0 0 6px 0';
  callHost.appendChild(callTitle);
  callHost.style.background = '#f7f7f9';
  callHost.style.border = '1px solid #e3e6ef';
  callHost.style.borderRadius = '12px';
  callHost.style.padding = '8px';

  const callStatePanel = document.createElement('div');
  callStatePanel.style.background = '#ffffff';
  callStatePanel.style.border = '1px solid #eceff5';
  callStatePanel.style.borderRadius = '12px';
  callStatePanel.style.padding = '10px 12px';
  callStatePanel.style.marginBottom = '8px';

  const callStateNode = document.createElement('div');
  callStateNode.style.fontSize = '13px';
  callStateNode.style.fontWeight = '700';
  callStateNode.style.color = '#2f3552';

  const callNoteNode = document.createElement('div');
  callNoteNode.style.fontSize = '12px';
  callNoteNode.style.color = '#555d74';
  callNoteNode.style.marginTop = '4px';

  callStatePanel.appendChild(callStateNode);
  callStatePanel.appendChild(callNoteNode);

  const callRuntimeNode = document.createElement('div');
  callRuntimeNode.style.fontSize = '12px';
  callRuntimeNode.style.color = '#3c4664';
  callRuntimeNode.style.marginTop = '6px';
  callStatePanel.appendChild(callRuntimeNode);

  const micMeterWrap = document.createElement('div');
  micMeterWrap.style.marginTop = '6px';
  micMeterWrap.style.height = '8px';
  micMeterWrap.style.borderRadius = '999px';
  micMeterWrap.style.background = '#e8ecf5';
  micMeterWrap.style.overflow = 'hidden';
  const micMeterBar = document.createElement('div');
  micMeterBar.style.height = '100%';
  micMeterBar.style.width = '0%';
  micMeterBar.style.background = 'linear-gradient(90deg, #22a06b 0%, #e2b203 65%, #d1242f 100%)';
  micMeterWrap.appendChild(micMeterBar);
  callStatePanel.appendChild(micMeterWrap);
  callHost.appendChild(callStatePanel);

  const callToInput = smsToInput;
  const callToHint = document.createElement('div');
  callToHint.textContent = '発信先: 上の「宛先」番号を使用';
  callToHint.style.fontSize = '12px';
  callToHint.style.color = '#55607a';
  callToHint.style.marginBottom = '6px';
  callHost.appendChild(callToHint);
  const btnStartCall = createButton('btnStartCall', '発信');
  const btnMute = createButton('btnMute', 'ミュート');
  const btnHangup = createButton('btnHangup', '終話');
  callHost.appendChild(btnStartCall);
  callHost.appendChild(btnMute);
  callHost.appendChild(btnHangup);

  const callPhaseLabel: Record<CallPhase, string> = {
    idle: '待機中',
    dialing: '発信中',
    ringing: '着信処理中',
    verifying: '認証中',
    in_call: '通話中',
    ended: '終了',
  };

  const syncCallUI = (phase: CallPhase, note?: string): void => {
    callStateNode.textContent = `状態: ${callPhaseLabel[phase]}`;
    callNoteNode.textContent = note ?? '';
    btnStartCall.disabled = !isAuthenticated || (phase !== 'idle' && phase !== 'ended');
    btnHangup.disabled = phase === 'idle' || phase === 'ended';
    btnMute.disabled = phase !== 'in_call';
    callHost.style.display = phase === 'idle' || phase === 'ended' ? 'none' : '';
    if (remoteAudioNode) {
      remoteAudioNode.style.display = phase === 'in_call' ? '' : 'none';
    }
  };
  syncCallUIRef = syncCallUI;
  syncCallUI(callPhase);

  const renderDuration = (): string => {
    if (!callStartedAt) return '00:00';
    const sec = Math.floor((Date.now() - callStartedAt) / 1000);
    const mm = String(Math.floor(sec / 60)).padStart(2, '0');
    const ss = String(sec % 60).padStart(2, '0');
    return `${mm}:${ss}`;
  };

  const syncCallRuntime = (): void => {
    const state = callPeer?.connectionState ?? 'idle';
    callRuntimeNode.textContent = `接続: ${state} / 通話時間: ${renderDuration()} / マイク: ${localMicMuted ? 'ミュート' : 'ON'}`;
    btnMute.textContent = localMicMuted ? 'ミュート解除' : 'ミュート';
    if (callPhase === 'in_call' && callTimerId === null) {
      callTimerId = window.setInterval(() => {
        callRuntimeNode.textContent = `接続: ${callPeer?.connectionState ?? 'idle'} / 通話時間: ${renderDuration()} / マイク: ${localMicMuted ? 'ミュート' : 'ON'}`;
      }, 1000);
    }
    if (callPhase !== 'in_call' && callTimerId !== null) {
      clearInterval(callTimerId);
      callTimerId = null;
    }
  };
  syncCallRuntimeRef = syncCallRuntime;
  syncCallRuntime();

  updateMicLevelRef = (level: number) => {
    micMeterBar.style.width = `${Math.round(level * 100)}%`;
  };

  const chatItems: ChatItem[] = [];
  const contactNames: Record<string, string> = {};
  let activeThreadNumber = '';

  const getDisplayName = (num: string): string => {
    const n = num.trim();
    if (!n) return '宛先未設定';
    const name = contactNames[n]?.trim();
    return name ? `${name} (${n})` : n;
  };

  const threadPeer = (msg: ChatItem): string => (msg.direction === 'out' ? msg.to : msg.from);

  const startComposeThread = (): void => {
    const raw = window.prompt('新しい宛先番号を入力');
    const num = raw?.trim() ?? '';
    if (!num) return;
    setActiveThread(num);
    if (isMobileChatLayout) {
      mobileChatPane = 'conversation';
      syncPaneVisibility();
    }
    smsBody.focus();
  };

  btnCreateThread.onclick = () => startComposeThread();

  const setActiveThread = (num: string): void => {
    activeThreadNumber = num.trim();
    if (activeThreadNumber) {
      smsToInput.value = activeThreadNumber;
      chatPeerLabel.textContent = getDisplayName(activeThreadNumber);
      peerNameInput.value = contactNames[activeThreadNumber] ?? '';
    }
    if (isMobileChatLayout) {
      mobileChatPane = 'conversation';
      syncPaneVisibility();
    }
    renderChatItems();
    renderThreadList();
  };

  const renderThreadList = (): void => {
    if (!threadListNode) return;
    threadListNode.innerHTML = '';
    const latestByPeer = new Map<string, ChatItem>();
    for (const item of chatItems) {
      const peer = threadPeer(item).trim();
      if (!peer) continue;
      const existing = latestByPeer.get(peer);
      if (!existing || item.timestamp >= existing.timestamp) {
        latestByPeer.set(peer, item);
      }
    }
    const rows = Array.from(latestByPeer.entries()).sort((a, b) => b[1].timestamp - a[1].timestamp);
    if (rows.length === 0) {
      return;
    }
    for (const [peer, latest] of rows) {
      const row = document.createElement('button');
      row.type = 'button';
      row.style.textAlign = 'left';
      row.style.border = 'none';
      row.style.borderBottom = '1px solid #f0f2fa';
      row.style.borderLeft = peer === activeThreadNumber ? '3px solid #6c63ff' : '3px solid transparent';
      row.style.borderRadius = '0';
      row.style.padding = '13px 14px';
      row.style.background = peer === activeThreadNumber ? '#f0eeff' : 'transparent';
      row.style.cursor = 'pointer';

      const head = document.createElement('div');
      head.style.fontSize = '13px';
      head.style.fontWeight = '700';
      head.style.color = '#1a1a2e';
      head.textContent = getDisplayName(peer);

      const preview = document.createElement('div');
      preview.style.marginTop = '3px';
      preview.style.fontSize = '11px';
      preview.style.color = '#7a82a0';
      preview.textContent = latest.body.slice(0, 36);

      row.appendChild(head);
      row.appendChild(preview);
      row.onclick = () => setActiveThread(peer);
      threadListNode.appendChild(row);
    }
  };

  const persistThread = (): void => {
    if (!currentNumber) return;
    void saveThread(currentNumber, chatItems, contactNames).catch(() => {});
  };

  const loadChatHistory = async (): Promise<void> => {
    chatItems.length = 0;
    for (const key of Object.keys(contactNames)) {
      delete contactNames[key];
    }
    if (!currentNumber) return;
    let rec: ChatThreadRecord | null = null;
    try {
      rec = await loadThread(currentNumber);
    } catch {
      // IndexedDB が利用できない環境ではチャット履歴なしで続行する
      return;
    }
    if (!rec) return;
    try {
      for (const it of rec.items ?? []) {
        if (!it || typeof it !== 'object') continue;
        if (!it.id || !it.body) continue;
        chatItems.push(it);
      }
      for (const [k, v] of Object.entries(rec.contacts ?? {})) {
        if (!k) continue;
        contactNames[k] = String(v ?? '');
      }
      chatItems.sort((a, b) => a.timestamp - b.timestamp);
    } catch {
      // ignore broken history
    }
  };

  const parseInboundMessage = (raw: unknown): ChatItem | null => {
    if (!raw || typeof raw !== 'object') return null;
    const obj = raw as Record<string, unknown>;
    const from = String(obj.from ?? obj.sender ?? '').trim();
    const to = String(obj.to ?? obj.receiver ?? currentNumber).trim();

    const msg = obj.message;
    const body =
      typeof msg === 'string'
        ? msg
        : msg && typeof msg === 'object'
          ? String((msg as Record<string, unknown>).body ?? '')
          : String(obj.body ?? '');
    const trimmedBody = body.trim();
    if (!trimmedBody) return null;

    const tsRaw = Number(obj.timestamp ?? obj.ts ?? Math.floor(Date.now() / 1000));
    const timestamp = Number.isFinite(tsRaw) ? Math.floor(tsRaw) : Math.floor(Date.now() / 1000);
    const direction: 'in' | 'out' = from && from === currentNumber ? 'out' : 'in';
    const id = `in-${from}-${to}-${timestamp}-${trimmedBody}`;

    return {
      id,
      from,
      to,
      body: trimmedBody,
      timestamp,
      direction,
      status: direction === 'in' ? 'received' : 'sent',
    };
  };

  const renderChatItems = (): void => {
    if (!messageFeedNode) return;
    messageFeedNode.innerHTML = '';
    const visible = activeThreadNumber
      ? chatItems.filter((x) => threadPeer(x).trim() === activeThreadNumber)
      : chatItems;
    const hasMessages = visible.length > 0;
    messageFeedNode.style.padding = hasMessages ? '10px 0' : '0';
    if (visible.length === 0) {
      return;
    }
    for (const msg of visible.slice(-80)) {
      const row = document.createElement('div');
      row.style.display = 'flex';
      row.style.justifyContent = msg.direction === 'out' ? 'flex-end' : 'flex-start';

      const bubble = document.createElement('div');
      bubble.style.maxWidth = '78%';
      bubble.style.padding = '9px 14px';
      bubble.style.borderRadius = msg.direction === 'out' ? '18px 18px 6px 18px' : '18px 18px 18px 6px';
      bubble.style.background = msg.direction === 'out' ? 'linear-gradient(135deg,#6c63ff,#4f8ef7)' : '#ffffff';
      bubble.style.color = msg.direction === 'out' ? '#ffffff' : '#1f2940';
      bubble.style.boxShadow = msg.direction === 'out' ? '0 3px 12px rgba(108,99,255,0.35)' : '0 2px 8px rgba(0,0,0,0.07)';

      const bodyNode = document.createElement('div');
      bodyNode.style.fontSize = '14px';
      bodyNode.style.lineHeight = '1.35';
      bodyNode.style.whiteSpace = 'pre-wrap';
      bodyNode.style.wordBreak = 'break-word';
      bodyNode.textContent = msg.body;

      const meta = document.createElement('div');
      meta.style.fontSize = '10px';
      meta.style.marginTop = '4px';
      meta.style.opacity = '0.75';
      const timeLabel = new Date(msg.timestamp * 1000).toLocaleTimeString();
      const stateLabel =
        msg.status === 'failed'
          ? `失敗 ${msg.reason ?? ''}`.trim()
          : msg.status === 'sending'
            ? '送信中'
            : msg.status === 'received'
              ? `受信 ${timeLabel}`
              : `送信 ${timeLabel}`;
      meta.textContent = msg.direction === 'in' ? stateLabel : `${timeLabel} ${stateLabel}`;

      bubble.appendChild(bodyNode);
      bubble.appendChild(meta);
      row.appendChild(bubble);
      messageFeedNode.appendChild(row);
    }
    messageFeedNode.scrollTop = messageFeedNode.scrollHeight;
  };
  renderChatItems();
  renderThreadList();

  syncMessageFeedRef = (messages: unknown[]) => {
    if (inboxNode) {
      inboxNode.textContent = JSON.stringify(messages, null, 2);
    }
    let changed = false;
    for (const raw of messages) {
      const parsed = parseInboundMessage(raw);
      if (!parsed) continue;
      if (chatItems.some((x) => x.id === parsed.id)) continue;
      chatItems.push(parsed);
      changed = true;
    }
    if (changed) {
      chatItems.sort((a, b) => a.timestamp - b.timestamp);
      if (!activeThreadNumber) {
        const latest = chatItems[chatItems.length - 1];
        if (latest) {
          activeThreadNumber = threadPeer(latest).trim();
          smsToInput.value = activeThreadNumber;
          chatPeerLabel.textContent = getDisplayName(activeThreadNumber);
          peerNameInput.value = contactNames[activeThreadNumber] ?? '';
        }
      }
      renderChatItems();
      renderThreadList();
      persistThread();
    }
  };

  remoteAudioNode = document.createElement('audio');
  remoteAudioNode.autoplay = true;
  remoteAudioNode.controls = true;
  remoteAudioNode.style.width = '100%';
  remoteAudioNode.style.marginTop = '8px';
  remoteAudioNode.style.display = 'none';
  callHost.appendChild(remoteAudioNode);

  signalInboxNode = null;

  const inboxTitle = document.createElement('h3');
  inboxTitle.textContent = '受信箱';
  inboxTitle.style.marginTop = '8px';
  inboxTitle.style.display = 'none';
  chatScreen.appendChild(inboxTitle);

  inboxNode = document.createElement('pre');
  inboxNode.id = 'inbox';
  inboxNode.style.background = '#ffffff';
  inboxNode.style.border = '1px solid #e7e4d9';
  inboxNode.style.padding = '12px';
  inboxNode.style.borderRadius = '12px';
  inboxNode.style.minHeight = '120px';
  inboxNode.style.whiteSpace = 'pre-wrap';
  inboxNode.style.wordBreak = 'break-word';
  inboxNode.style.fontSize = '12px';
  inboxNode.style.display = 'none';
  chatScreen.appendChild(inboxNode);

  screens.login = loginScreen;
  screens.signup = signupScreen;
  screens.reset = resetScreen;
  screens.chat = chatScreen;

  const screenKeys: ScreenKey[] = ['login', 'signup', 'reset', 'chat'];
  for (const key of screenKeys) {
    screenHost.appendChild(screens[key]);
  }

  disconnectXButton = document.createElement('button');
  disconnectXButton.type = 'button';
  disconnectXButton.textContent = '×';
  disconnectXButton.title = '切断';
  disconnectXButton.style.position = 'fixed';
  disconnectXButton.style.top = '14px';
  disconnectXButton.style.right = '14px';
  disconnectXButton.style.width = '36px';
  disconnectXButton.style.height = '36px';
  disconnectXButton.style.border = 'none';
  disconnectXButton.style.borderRadius = '999px';
  disconnectXButton.style.background = 'rgba(108,99,255,0.15)';
  disconnectXButton.style.color = '#6c63ff';
  disconnectXButton.style.cursor = 'pointer';
  disconnectXButton.style.fontSize = '20px';
  disconnectXButton.style.lineHeight = '1';
  disconnectXButton.style.display = 'none';
  disconnectXButton.style.backdropFilter = 'blur(8px)';
  disconnectXButton.onclick = () => {
    closeNodeWS();
    currentChallenge = '';
    pendingCallAuth = null;
    setStatus('disconnected');
  };
  container.appendChild(disconnectXButton);
  container.appendChild(screenHost);

  root.appendChild(container);
  syncAuthUI();
  setActiveScreen('login');

  let isLoggingIn = false;
  const doLogin = async (opts?: { silent?: boolean }): Promise<void> => {
    if (isLoggingIn) throw new Error('ログイン処理中です。完了をお待ちください');
    isLoggingIn = true;
    try {
    currentNumber = numberInput.value.trim();
    const mnemonicValue = mnemonicLoginTextarea.value.trim();
    let privateKeyHex: string;
    if (mnemonicValue) {
      privateKeyHex = await mnemonicToPrivateKeyHex(mnemonicValue);
    } else if (privateKeyInput.value.trim()) {
      privateKeyHex = normalizePrivateKeyHex(privateKeyInput.value);
    } else {
      // 保存済みの暗号化鍵を復元する
      const savedEncrypted = localStorage.getItem(LS_ENCRYPTED_KEY) ?? '';
      if (!savedEncrypted) throw new Error('秘密鍵またはニーモニックを入力してください');
      const password = savePasswordInput.value;
      if (!password) throw new Error('保存済みの鍵を使うにはパスワードを入力してください');
      privateKeyHex = normalizePrivateKeyHex(await decryptPrivateKey(savedEncrypted, password));
    }

    if (!currentNumber) {
      throw new Error('number は必須');
    }

    // セッション中のみメモリに保持（persist=offでも通話認証・SMS署名で使用）
    currentPrivateKeyHex = privateKeyHex;

    localStorage.setItem(LS_PERSIST_SENSITIVE, persistSensitiveCheck.checked ? '1' : '0');
    if (persistSensitiveCheck.checked) {
      const password = savePasswordInput.value;
      if (!password) throw new Error('端末保存にはパスワードを入力してください');
      validateSavePassword(password);
      const encrypted = await encryptPrivateKey(privateKeyHex, password);
      localStorage.setItem(LS_ENCRYPTED_KEY, encrypted);
    } else {
      localStorage.removeItem(LS_ENCRYPTED_KEY);
      localStorage.removeItem(LS_PUBLIC_KEY);
    }
    const derivedPubHex = derivePublicKeyHex(privateKeyHex);
    if (persistSensitiveCheck.checked) {
      localStorage.setItem(LS_PUBLIC_KEY, derivedPubHex);
    }

    const seed = await resolveSeed(currentNumber);
    windowBase = seed.windowBase;
    localStorage.setItem(LS_WINDOW_BASE, windowBase);

    if (persistSensitiveCheck.checked) {
      localStorage.setItem(LS_NUMBER, currentNumber);
      localStorage.setItem(LS_PHONE_NUMBER, currentNumber);
    } else {
      localStorage.removeItem(LS_NUMBER);
      localStorage.removeItem(LS_PHONE_NUMBER);
    }
    smsFromInput.value = currentNumber;

    nodeWsUrl = seed.nodeWs;
    if (!nodeWsUrl) throw new Error('node ws resolve failed');

    if (!opts?.silent) setStatus(`number: ${currentNumber}, connecting to ${nodeWsUrl} ...`);
    await openNodeWS(currentNumber);
    if (!opts?.silent) setStatus(`connected as ${currentNumber}, requesting challenge ...`);

    const challenge = await requestChallengeOnce();
    const sigHex = makeAuthSignatureHex(currentNumber, challenge, privateKeyHex);
    sendAuthVerify(sigHex);
    await waitAuthenticated();
    setCallPhase('idle');
    await loadChatHistory();
    if (!activeThreadNumber && chatItems.length > 0) {
      const latest = chatItems[chatItems.length - 1];
      if (latest) {
        activeThreadNumber = threadPeer(latest).trim();
        smsToInput.value = activeThreadNumber;
        peerNameInput.value = contactNames[activeThreadNumber] ?? '';
      }
    }
    renderChatItems();
    renderThreadList();
    chatPeerLabel.textContent = getDisplayName(smsToInput.value.trim());

    if (!opts?.silent) setStatus(`ログイン成功: ${currentNumber}`);
    setActiveScreen('chat');
    } finally {
      isLoggingIn = false;
    }
  };

  btnLookupConnect.onclick = async () => {
    if (btnLookupConnect.disabled) return;
    btnLookupConnect.disabled = true;
    try {
      await doLogin();
    } catch (err) {
      setErrorStatus(err);
    } finally {
      btnLookupConnect.disabled = false;
    }
  };

  btnRegister.onclick = async () => {
    try {
      const route = normalizeRoutingNumber(signupRouteInput.value);
      const seed = await resolveSeed(route);
      windowBase = seed.windowBase;
      localStorage.setItem(LS_WINDOW_BASE, windowBase);
      await registerEmail(windowBase, signupEmailInput.value.trim());
      setStatus('確認メールを送信しました。トークンを入力してください。');
      signupStep1.style.display = 'none';
      signupStep2.style.display = 'block';
      btnRegister.style.display = 'none';
      btnCreate.style.display = '';
      btnCreate.disabled = true;
      signupConfirmCheck.checked = false;
      // ステップ2に入ったタイミングで新しい秘密鍵を生成する
      generateAndShowMnemonic(signupMnemonicGrid, signupMnemonicStatus, (hex) => { signupGeneratedKeyHex = hex; }, signupConfirmCheck, btnCreate);
      signupTokenInput.focus();
    } catch (err) {
      setErrorStatus(err);
    }
  };

  btnCreate.onclick = async () => {
    try {
      if (!signupGeneratedKeyHex) throw new Error('秘密鍵が生成されていません。再生成してください。');
      if (!signupConfirmCheck.checked) throw new Error('ニーモニックを控えたことを確認してください。');
      const route = normalizeRoutingNumber(signupRouteInput.value);
      const seed = await resolveSeed(route);
      windowBase = seed.windowBase;
      localStorage.setItem(LS_WINDOW_BASE, windowBase);
      const privateKeyHex = signupGeneratedKeyHex;
      const pubHex = derivePublicKeyHex(privateKeyHex);
      if (persistSensitiveCheck.checked) {
        const password = savePasswordInput.value;
        if (!password) throw new Error('端末保存にはパスワードを入力してください');
        validateSavePassword(password);
        const encrypted = await encryptPrivateKey(privateKeyHex, password);
        localStorage.setItem(LS_ENCRYPTED_KEY, encrypted);
        localStorage.setItem(LS_PUBLIC_KEY, pubHex);
      } else {
        localStorage.removeItem(LS_ENCRYPTED_KEY);
        localStorage.removeItem(LS_PUBLIC_KEY);
      }
      const number = await createAccount(windowBase, signupTokenInput.value.trim(), pubHex);
      setStatus(`account created: ${number}`);
      numberInput.value = number;
      // ログイン画面に戻った際に再入力不要なように秘密鍵を転記（type='password'でマスク済み）
      privateKeyInput.value = privateKeyHex;
      currentNumber = number;
      if (persistSensitiveCheck.checked) {
        localStorage.setItem(LS_NUMBER, number);
        localStorage.setItem(LS_PHONE_NUMBER, number);
      }
      setActiveScreen('login');
    } catch (err) {
      setErrorStatus(err);
    }
  };

  btnResetReq.onclick = async () => {
    try {
      const route = normalizeRoutingNumber(resetRouteInput.value);
      const seed = await resolveSeed(route);
      windowBase = seed.windowBase;
      localStorage.setItem(LS_WINDOW_BASE, windowBase);
      await resetRequest(windowBase, resetEmailInput.value.trim());
      setStatus('再設定メールを送信しました。トークンを入力してください。');
      resetStep1.style.display = 'none';
      resetStep2.style.display = 'block';
      btnResetReq.style.display = 'none';
      btnResetDo.style.display = '';
      btnResetDo.disabled = true;
      resetConfirmCheck.checked = false;
      // ステップ2に入ったタイミングで新しい秘密鍵を生成する
      generateAndShowMnemonic(resetMnemonicGrid, resetMnemonicStatus, (hex) => { resetGeneratedKeyHex = hex; }, resetConfirmCheck, btnResetDo);
      resetTokenInput.focus();
    } catch (err) {
      setErrorStatus(err);
    }
  };

  btnResetDo.onclick = async () => {
    try {
      if (!resetGeneratedKeyHex) throw new Error('秘密鍵が生成されていません。再生成してください。');
      if (!resetConfirmCheck.checked) throw new Error('ニーモニックを控えたことを確認してください。');
      const route = normalizeRoutingNumber(resetRouteInput.value);
      const seed = await resolveSeed(route);
      windowBase = seed.windowBase;
      localStorage.setItem(LS_WINDOW_BASE, windowBase);
      const privateKeyHex = resetGeneratedKeyHex;
      const pubHex = derivePublicKeyHex(privateKeyHex);
      if (persistSensitiveCheck.checked) {
        const password = savePasswordInput.value;
        if (!password) throw new Error('端末保存にはパスワードを入力してください');
        validateSavePassword(password);
        const encrypted = await encryptPrivateKey(privateKeyHex, password);
        localStorage.setItem(LS_ENCRYPTED_KEY, encrypted);
        localStorage.setItem(LS_PUBLIC_KEY, pubHex);
      } else {
        localStorage.removeItem(LS_ENCRYPTED_KEY);
        localStorage.removeItem(LS_PUBLIC_KEY);
      }
      const number = await resetDo(windowBase, resetTokenInput.value.trim(), pubHex);
      setStatus(`reset done: ${number}`);
      numberInput.value = number;
      // ログイン画面に戻った際に再入力不要なように秘密鍵を転記（type='password'でマスク済み）
      privateKeyInput.value = privateKeyHex;
      currentNumber = number;
      if (persistSensitiveCheck.checked) {
        localStorage.setItem(LS_NUMBER, number);
        localStorage.setItem(LS_PHONE_NUMBER, number);
      }
      setActiveScreen('login');
    } catch (err) {
      setErrorStatus(err);
    }
  };

  btnSendSMS.onclick = async () => {
    if (btnSendSMS.disabled) return;
    btnSendSMS.disabled = true;
    let pendingId = '';
    try {
      ensureAuthenticated();
      const to = smsToInput.value.trim();
      const from = currentNumber;
      const body = smsBody.value;
      const timestamp = Math.floor(Date.now() / 1000);

      if (!to) throw new Error('to is required');
      if (!from) throw new Error('from is required');
      if (!body) throw new Error('message is required');
      // セッション変数を使用する（未ログイン状態ではここに到達しないが念のためチェック）
      const rawPrivKey = currentPrivateKeyHex || privateKeyInput.value.trim();
      if (!rawPrivKey) throw new Error('セッションが切れました。再ログインしてください。');
      const privateKeyHex = normalizePrivateKeyHex(rawPrivKey);
      const sig = makeMessageSignatureHex(from, to, { body }, timestamp, privateKeyHex);

      pendingId = crypto.randomUUID();
      chatItems.push({
        id: pendingId,
        from,
        to,
        body,
        timestamp,
        direction: 'out',
        status: 'sending',
      });
      activeThreadNumber = to;
      renderChatItems();
      renderThreadList();
      persistThread();

      await sendSMS(windowBase, to, from, body, sig, timestamp);
      const target = chatItems.find((x) => x.id === pendingId);
      if (target) target.status = 'sent';
      renderChatItems();
      renderThreadList();
      persistThread();
      setStatus('sms sent');
      smsBody.value = '';
    } catch (err) {
      const failed = pendingId ? chatItems.find((x) => x.id === pendingId) : null;
      if (failed) {
        failed.status = 'failed';
        failed.reason = toErrorText(err);
        renderChatItems();
        renderThreadList();
        persistThread();
      }
      setErrorStatus(err);
    } finally {
      btnSendSMS.disabled = false;
    }
  };

  smsBody.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      btnSendSMS.click();
    }
  });

  const startCallFlow = async (): Promise<void> => {
    try {
      ensureAuthenticated();
      const to = callToInput.value.trim();
      const from = currentNumber;
      if (!to) throw new Error('call to is required');
      if (!from) throw new Error('from is required');
      const pc = await ensurePeerForTarget(to);
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await sendICEOffer(windowBase, { from, to, offer: pc.localDescription?.toJSON() ?? offer });
      setCallPhase('dialing', `${to} に発信中`);
      setStatus('call offer sent');
    } catch (err) {
      setErrorStatus(err);
    }
  };
  btnStartCall.onclick = () => {
    void startCallFlow();
  };
  btnHeaderCall.onclick = () => {
    void startCallFlow();
  };

  btnHangup.onclick = async () => {
    const peer = activeCallPeer;
    const from = currentNumber;
    cleanupCall();
    pendingCallAuth = null;
    setCallPhase('ended', 'こちらから終話');
    if (peer && from) {
      try {
        await sendCallHangup(windowBase, { from, to: peer });
      } catch {
        // ignore network errors on hangup notice
      }
    }
    setStatus('call ended');
  };

  btnMute.onclick = async () => {
    try {
      if (!localStream) {
        await ensureLocalStream();
      }
      if (!localStream) return;
      localMicMuted = !localMicMuted;
      for (const track of localStream.getAudioTracks()) {
        track.enabled = !localMicMuted;
      }
      if (syncCallRuntimeRef) syncCallRuntimeRef();
    } catch (err) {
      setErrorStatus(err);
    }
  };

  // 起動時: 旧形式（プレーンテキスト）の秘密鍵が残っていれば移行を促す
  const legacyPlainKey = localStorage.getItem(LS_PRIVATE_KEY);
  if (legacyPlainKey && !localStorage.getItem(LS_ENCRYPTED_KEY)) {
    // 旧鍵を秘密鍵入力欄に転記してユーザーにパスワードを設定させる
    privateKeyInput.value = legacyPlainKey;
    // 旧鍵を削除（平文で保存しない）
    localStorage.removeItem(LS_PRIVATE_KEY);
    privateKeySection.style.display = 'block';
    privateKeyToggle.textContent = '▼ 秘密鍵で直接ログインする';
    setStatus('セキュリティのため保存形式が変更されました。「端末に保存」にチェックを入れてパスワードを設定し、再度ログインしてください（チェックなしでもログインできます）。');
  } else if (localStorage.getItem(LS_PRIVATE_KEY)) {
    localStorage.removeItem(LS_PRIVATE_KEY);
  }

  const savedNumber = (localStorage.getItem(LS_PHONE_NUMBER) ?? localStorage.getItem(LS_NUMBER) ?? '').trim();
  const savedEncryptedKey = (localStorage.getItem(LS_ENCRYPTED_KEY) ?? '').trim();
  const persistSensitiveEnabled = (localStorage.getItem(LS_PERSIST_SENSITIVE) ?? '1') !== '0';
  persistSensitiveCheck.checked = persistSensitiveEnabled;
  if (persistSensitiveEnabled && savedNumber && savedEncryptedKey) {
    numberInput.value = savedNumber;
    // パスワード入力欄を表示してログインを促す（自動ログインは行わない）
    savePasswordGroup.style.display = 'block';
    setStatus('保存済みのデータがあります。パスワードを入力してログインしてください。');
  }
}