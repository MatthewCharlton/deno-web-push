// src/crypto.ts
import * as cryptoHelpers from "https://esm.sh/crypto-browserify?bundle";
var crypto_default = cryptoHelpers;

// src/vapid-helper.ts
import { Buffer } from "https://deno.land/std@0.147.0/node/buffer.ts";
import { parse } from "https://deno.land/std@0.146.0/node/url.ts";
import * as jws from "https://esm.sh/jws@4.0.0?target=es2020";
import asn1 from "https://esm.sh/asn1.js@5.4.1?target=es2020";
import {
  encode,
  validate,
  decode
} from "https://esm.sh/urlsafe-base64@1.0.0?target=es2020";

// src/web-push-constants.ts
var WebPushConstants = {};
var supportedContentEncodings = {
  AES_GCM: "aesgcm",
  AES_128_GCM: "aes128gcm"
};
WebPushConstants.supportedContentEncodings = supportedContentEncodings;
var web_push_constants_default = WebPushConstants;

// src/vapid-helper.ts
var DEFAULT_EXPIRATION_SECONDS = 12 * 60 * 60;
var MAX_EXPIRATION_SECONDS = 24 * 60 * 60;
var ECPrivateKeyASN = asn1.define("ECPrivateKey", function() {
  this.seq().obj(this.key("version").int(), this.key("privateKey").octstr(), this.key("parameters").explicit(0).objid().optional(), this.key("publicKey").explicit(1).bitstr().optional());
});
function toPEM(key) {
  return ECPrivateKeyASN.encode({
    version: 1,
    privateKey: key,
    parameters: [1, 2, 840, 10045, 3, 1, 7]
  }, "pem", {
    label: "EC PRIVATE KEY"
  });
}
function generateVAPIDKeys() {
  const curve = crypto_default.createECDH("prime256v1");
  curve.generateKeys();
  let publicKeyBuffer = curve.getPublicKey();
  let privateKeyBuffer = curve.getPrivateKey();
  if (privateKeyBuffer.length < 32) {
    const padding = Buffer.alloc(32 - privateKeyBuffer.length);
    padding.fill(0);
    privateKeyBuffer = Buffer.concat([padding, privateKeyBuffer]);
  }
  if (publicKeyBuffer.length < 65) {
    const padding = Buffer.alloc(65 - publicKeyBuffer.length);
    padding.fill(0);
    publicKeyBuffer = Buffer.concat([padding, publicKeyBuffer]);
  }
  return {
    publicKey: encode(publicKeyBuffer),
    privateKey: encode(privateKeyBuffer)
  };
}
function validateSubject(subject) {
  if (!subject) {
    throw new Error("No subject set in vapidDetails.subject.");
  }
  if (typeof subject !== "string" || subject.length === 0) {
    throw new Error("The subject value must be a string containing a URL or mailto: address. " + subject);
  }
  if (subject.indexOf("mailto:") !== 0) {
    const subjectParseResult = parse(subject, false, false);
    if (!subjectParseResult.hostname) {
      throw new Error("Vapid subject is not a url or mailto url. " + subject);
    }
  }
}
function validatePublicKey(publicKey) {
  if (!publicKey) {
    throw new Error("No key set vapidDetails.publicKey");
  }
  if (typeof publicKey !== "string") {
    throw new Error("Vapid public key is must be a URL safe Base 64 encoded string.");
  }
  if (!validate(publicKey)) {
    throw new Error('Vapid public key must be a URL safe Base 64 (without "=")');
  }
  publicKey = decode(publicKey);
  if (publicKey.length !== 65) {
    throw new Error("Vapid public key should be 65 bytes long when decoded.");
  }
}
function validatePrivateKey(privateKey) {
  if (!privateKey) {
    throw new Error("No key set in vapidDetails.privateKey");
  }
  if (typeof privateKey !== "string") {
    throw new Error("Vapid private key must be a URL safe Base 64 encoded string.");
  }
  if (!validate(privateKey)) {
    throw new Error('Vapid private key must be a URL safe Base 64 (without "=")');
  }
  privateKey = decode(privateKey);
  if (privateKey.length !== 32) {
    throw new Error("Vapid private key should be 32 bytes long when decoded.");
  }
}
function getFutureExpirationTimestamp(numSeconds) {
  const futureExp = new Date();
  futureExp.setSeconds(futureExp.getSeconds() + numSeconds);
  return Math.floor(futureExp.getTime() / 1e3);
}
function validateExpiration(expiration) {
  if (!Number.isInteger(expiration)) {
    throw new Error("`expiration` value must be a number");
  }
  if (expiration < 0) {
    throw new Error("`expiration` must be a positive integer");
  }
  const maxExpirationTimestamp = getFutureExpirationTimestamp(MAX_EXPIRATION_SECONDS);
  if (expiration >= maxExpirationTimestamp) {
    throw new Error("`expiration` value is greater than maximum of 24 hours");
  }
}
function getVapidHeaders(audience, subject, publicKey, privateKey, contentEncoding, expiration) {
  if (!audience) {
    throw new Error("No audience could be generated for VAPID.");
  }
  if (typeof audience !== "string" || audience.length === 0) {
    throw new Error("The audience value must be a string containing the origin of a push service. " + audience);
  }
  const audienceParseResult = parse(audience, false, false);
  if (!audienceParseResult.hostname) {
    throw new Error("VAPID audience is not a url. " + audience);
  }
  validateSubject(subject);
  validatePublicKey(publicKey);
  validatePrivateKey(privateKey);
  if (expiration) {
    validateExpiration(expiration);
  } else {
    expiration = getFutureExpirationTimestamp(DEFAULT_EXPIRATION_SECONDS);
  }
  const header = {
    typ: "JWT",
    alg: "ES256"
  };
  const jwtPayload = {
    aud: audience,
    exp: expiration,
    sub: subject
  };
  const jwt = jws.sign({
    header,
    payload: jwtPayload,
    privateKey: toPEM(privateKey)
  });
  console.log("jwt", jwt);
  console.log("contentEncoding", contentEncoding);
  if (contentEncoding === supportedContentEncodings.AES_128_GCM) {
    console.log(JSON.stringify({
      Authorization: "vapid t=" + jwt + ", k=" + publicKey
    }));
    return {
      Authorization: "vapid t=" + jwt + ", k=" + publicKey
    };
  }
  if (contentEncoding === supportedContentEncodings.AES_GCM) {
    console.log(JSON.stringify({
      Authorization: "WebPush " + jwt,
      "Crypto-Key": "p256ecdsa=" + publicKey
    }));
    return {
      Authorization: "WebPush " + jwt,
      "Crypto-Key": "p256ecdsa=" + publicKey
    };
  }
  throw new Error("Unsupported encoding type specified.");
}

// src/encryption-helper.ts
import { Buffer as Buffer3 } from "https://deno.land/std@0.147.0/node/buffer.ts";

// src/ece.ts
import { Buffer as Buffer2 } from "https://deno.land/std@0.147.0/node/buffer.ts";
import * as base64 from "https://esm.sh/urlsafe-base64@1.0.0?target=es2020";
var AES_GCM = "aes-128-gcm";
var PAD_SIZE = { aes128gcm: 1, aesgcm: 2 };
var TAG_LENGTH = 16;
var KEY_LENGTH = 16;
var NONCE_LENGTH = 12;
var SHA_256_LENGTH = 32;
var MODE_ENCRYPT = "encrypt";
var MODE_DECRYPT = "decrypt";
var keylog;
keylog = function(m, k) {
  return k;
};
function decode3(b) {
  if (typeof b === "string") {
    return base64.decode(b);
  }
  return b;
}
function HMAC_hash(key, input) {
  const hmac = crypto_default.createHmac("sha256", key);
  hmac.update(input);
  return hmac.digest();
}
function HKDF_extract(salt, ikm) {
  keylog("salt", salt);
  keylog("ikm", ikm);
  return keylog("extract", HMAC_hash(salt, ikm));
}
function HKDF_expand(prk, info2, l) {
  keylog("prk", prk);
  keylog("info", info2);
  let output = Buffer2.alloc(0);
  let T = Buffer2.alloc(0);
  info2 = Buffer2.from(info2, "ascii");
  let counter = 0;
  const cbuf = Buffer2.alloc(1);
  while (output.length < l) {
    cbuf.writeUIntBE(++counter, 0, 1);
    T = HMAC_hash(prk, Buffer2.concat([T, info2, cbuf]));
    output = Buffer2.concat([output, T]);
  }
  return keylog("expand", output.slice(0, l));
}
function HKDF(salt, ikm, info2, len) {
  return HKDF_expand(HKDF_extract(salt, ikm), info2, len);
}
function info(base, context) {
  const result = Buffer2.concat([
    Buffer2.from("Content-Encoding: " + base + "\0", "ascii"),
    context
  ]);
  keylog("info " + base, result);
  return result;
}
function lengthPrefix(buffer) {
  const b = Buffer2.concat([Buffer2.alloc(2), buffer]);
  b.writeUIntBE(buffer.length, 0, 2);
  return b;
}
function extractDH(header, mode) {
  const key = header.privateKey;
  let senderPubKey, receiverPubKey;
  if (mode === MODE_ENCRYPT) {
    senderPubKey = key.getPublicKey();
    receiverPubKey = header.dh;
  } else if (mode === MODE_DECRYPT) {
    senderPubKey = header.dh;
    receiverPubKey = key.getPublicKey();
  } else {
    throw new Error("Unknown mode only " + MODE_ENCRYPT + " and " + MODE_DECRYPT + " supported");
  }
  return {
    secret: key.computeSecret(header.dh),
    context: Buffer2.concat([
      Buffer2.from(header.keylabel, "ascii"),
      Buffer2.from([0]),
      lengthPrefix(receiverPubKey),
      lengthPrefix(senderPubKey)
    ])
  };
}
function extractSecretAndContext(header, mode) {
  let result = { secret: null, context: Buffer2.alloc(0) };
  if (header.key) {
    result.secret = header.key;
    if (result.secret !== null && result.secret.length !== KEY_LENGTH) {
      throw new Error("An explicit key must be " + KEY_LENGTH + " bytes");
    }
  } else if (header.dh) {
    result = extractDH(header, mode);
  } else if (header.keyid !== void 0) {
    result.secret = header.keymap[header.keyid];
  }
  if (!result.secret) {
    throw new Error("Unable to determine key");
  }
  keylog("secret", result.secret);
  keylog("context", result.context);
  if (header.authSecret) {
    result.secret = HKDF(header.authSecret, result.secret, info("auth", Buffer2.alloc(0)), SHA_256_LENGTH);
    keylog("authsecret", result.secret);
  }
  return result;
}
function webpushSecret(header, mode) {
  if (!header.authSecret) {
    throw new Error("No authentication secret for webpush");
  }
  keylog("authsecret", header.authSecret);
  let remotePubKey, senderPubKey, receiverPubKey;
  if (mode === MODE_ENCRYPT) {
    senderPubKey = header.privateKey.getPublicKey();
    remotePubKey = receiverPubKey = header.dh;
  } else if (mode === MODE_DECRYPT) {
    remotePubKey = senderPubKey = header.keyid;
    receiverPubKey = header.privateKey.getPublicKey();
  } else {
    throw new Error("Unknown mode only " + MODE_ENCRYPT + " and " + MODE_DECRYPT + " supported");
  }
  keylog("remote pubkey", remotePubKey);
  keylog("sender pubkey", senderPubKey);
  keylog("receiver pubkey", receiverPubKey);
  return keylog("secret dh", HKDF(header.authSecret, header.privateKey.computeSecret(remotePubKey), Buffer2.concat([
    Buffer2.from("WebPush: info\0"),
    receiverPubKey,
    senderPubKey
  ]), SHA_256_LENGTH));
}
function extractSecret(header, mode, keyLookupCallback) {
  if (keyLookupCallback) {
    if (!isFunction(keyLookupCallback)) {
      throw new Error("Callback is not a function");
    }
  }
  if (header.key) {
    if (header.key.length !== KEY_LENGTH) {
      throw new Error("An explicit key must be " + KEY_LENGTH + " bytes");
    }
    return keylog("secret key", header.key);
  }
  if (!header.privateKey) {
    let key;
    if (!keyLookupCallback) {
      key = header.keymap && header.keymap[header.keyid];
    } else {
      key = keyLookupCallback(header.keyid);
    }
    if (!key) {
      throw new Error('No saved key (keyid: "' + header.keyid + '")');
    }
    return key;
  }
  return webpushSecret(header, mode);
}
function deriveKeyAndNonce(header, mode, lookupKeyCallback) {
  if (!header.salt) {
    throw new Error("must include a salt parameter for " + header.version);
  }
  let keyInfo;
  let nonceInfo;
  let secret;
  if (header.version === "aesgcm") {
    const s = extractSecretAndContext(header, mode, lookupKeyCallback);
    keyInfo = info("aesgcm", s.context);
    nonceInfo = info("nonce", s.context);
    secret = s.secret;
  } else if (header.version === "aes128gcm") {
    keyInfo = Buffer2.from("Content-Encoding: aes128gcm\0");
    nonceInfo = Buffer2.from("Content-Encoding: nonce\0");
    secret = extractSecret(header, mode, lookupKeyCallback);
  } else {
    throw new Error("Unable to set context for mode " + header.version);
  }
  const prk = HKDF_extract(header.salt, secret);
  const result = {
    key: HKDF_expand(prk, keyInfo, KEY_LENGTH),
    nonce: HKDF_expand(prk, nonceInfo, NONCE_LENGTH)
  };
  keylog("key", result.key);
  keylog("nonce base", result.nonce);
  return result;
}
function parseParams(params) {
  const header = {};
  header.version = params.version || "aes128gcm";
  header.rs = parseInt(params.rs, 10);
  if (isNaN(header.rs)) {
    header.rs = 4096;
  }
  let overhead = PAD_SIZE[header.version];
  if (header.version === "aes128gcm") {
    overhead += TAG_LENGTH;
  }
  if (header.rs <= overhead) {
    throw new Error("The rs parameter has to be greater than " + overhead);
  }
  if (params.salt) {
    header.salt = decode3(params.salt);
    if (header.salt.length !== KEY_LENGTH) {
      throw new Error("The salt parameter must be " + KEY_LENGTH + " bytes");
    }
  }
  header.keyid = params.keyid;
  if (params.key) {
    header.key = decode3(params.key);
  } else {
    header.privateKey = params.privateKey;
    if (!header.privateKey) {
      header.keymap = params.keymap;
    }
    if (header.version !== "aes128gcm") {
      header.keylabel = params.keylabel || "P-256";
    }
    if (params.dh) {
      header.dh = decode3(params.dh);
    }
  }
  if (params.authSecret) {
    header.authSecret = decode3(params.authSecret);
  }
  return header;
}
function generateNonce(base, counter) {
  const nonce = Buffer2.from(base);
  const m = nonce.readUIntBE(nonce.length - 6, 6);
  const x = ((m ^ counter) & 16777215) + ((m / 16777216 ^ counter / 16777216) & 16777215) * 16777216;
  nonce.writeUIntBE(x, nonce.length - 6, 6);
  keylog("nonce" + counter, nonce);
  return nonce;
}
function encryptRecord(key, counter, buffer, pad, header, last) {
  keylog("encrypt", buffer);
  pad = pad || 0;
  const nonce = generateNonce(key.nonce, counter);
  const gcm = crypto_default.createCipheriv(AES_GCM, key.key, nonce);
  const ciphertext = [];
  const padSize = PAD_SIZE[header.version];
  const padding = Buffer2.alloc(pad + padSize);
  padding.fill(0);
  if (header.version !== "aes128gcm") {
    padding.writeUIntBE(pad, 0, padSize);
    keylog("padding", padding);
    ciphertext.push(gcm.update(padding));
    ciphertext.push(gcm.update(buffer));
    if (!last && padding.length + buffer.length < header.rs) {
      throw new Error("Unable to pad to record size");
    }
  } else {
    ciphertext.push(gcm.update(buffer));
    padding.writeUIntBE(last ? 2 : 1, 0, 1);
    keylog("padding", padding);
    ciphertext.push(gcm.update(padding));
  }
  gcm.final();
  const tag = gcm.getAuthTag();
  if (tag.length !== TAG_LENGTH) {
    throw new Error("invalid tag generated");
  }
  ciphertext.push(tag);
  return keylog("encrypted", Buffer2.concat(ciphertext));
}
function writeHeader(header) {
  const ints = Buffer2.alloc(5);
  const keyid = Buffer2.from(header.keyid || []);
  if (keyid.length > 255) {
    throw new Error("keyid is too large");
  }
  ints.writeUIntBE(header.rs, 0, 4);
  ints.writeUIntBE(keyid.length, 4, 1);
  return Buffer2.concat([header.salt, ints, keyid]);
}
function encrypt(buffer, params, keyLookupCallback) {
  if (!Buffer2.isBuffer(buffer)) {
    throw new Error("buffer argument must be a Buffer");
  }
  const header = parseParams(params);
  if (!header.salt) {
    header.salt = crypto_default.randomBytes(KEY_LENGTH);
  }
  let result;
  if (header.version === "aes128gcm") {
    if (header.privateKey && !header.keyid) {
      header.keyid = header.privateKey.getPublicKey();
    }
    result = writeHeader(header);
  } else {
    result = Buffer2.alloc(0);
  }
  const key = deriveKeyAndNonce(header, MODE_ENCRYPT, keyLookupCallback);
  let start = 0;
  const padSize = PAD_SIZE[header.version];
  let overhead = padSize;
  if (header.version === "aes128gcm") {
    overhead += TAG_LENGTH;
  }
  let pad = isNaN(parseInt(params.pad, 10)) ? 0 : parseInt(params.pad, 10);
  let counter = 0;
  let last = false;
  while (!last) {
    let recordPad = Math.min(header.rs - overhead - 1, pad);
    if (header.version !== "aes128gcm") {
      recordPad = Math.min((1 << padSize * 8) - 1, recordPad);
    }
    if (pad > 0 && recordPad === 0) {
      ++recordPad;
    }
    pad -= recordPad;
    const end = start + header.rs - overhead - recordPad;
    if (header.version !== "aes128gcm") {
      last = end > buffer.length;
    } else {
      last = end >= buffer.length;
    }
    last = last && pad <= 0;
    const block = encryptRecord(key, counter, buffer.slice(start, end), recordPad, header, last);
    result = Buffer2.concat([result, block]);
    start = end;
    ++counter;
  }
  return result;
}
function isFunction(object) {
  return typeof object === "function";
}

// src/encryption-helper.ts
import * as urlBase64 from "https://esm.sh/urlsafe-base64@1.0.0?target=es2020";
var encrypt2 = function(userPublicKey, userAuth, payload, contentEncoding) {
  if (!userPublicKey) {
    throw new Error("No user public key provided for encryption.");
  }
  if (typeof userPublicKey !== "string") {
    throw new Error("The subscription p256dh value must be a string.");
  }
  if (urlBase64.decode(userPublicKey).length !== 65) {
    throw new Error("The subscription p256dh value should be 65 bytes long.");
  }
  if (!userAuth) {
    throw new Error("No user auth provided for encryption.");
  }
  if (typeof userAuth !== "string") {
    throw new Error("The subscription auth key must be a string.");
  }
  if (urlBase64.decode(userAuth).length < 16) {
    throw new Error("The subscription auth key should be at least 16 bytes long");
  }
  if (payload instanceof Uint8Array) {
    payload = Buffer3(payload);
  }
  if (typeof payload !== "string" && !Buffer3.isBuffer(payload)) {
    throw new Error("Payload must be either a string or a Node Buffer.");
  }
  if (typeof payload === "string" || payload instanceof String) {
    payload = Buffer3.from(payload);
  }
  const localCurve = crypto_default.createECDH("prime256v1");
  const localPublicKey = localCurve.generateKeys();
  const salt = urlBase64.encode(crypto_default.randomBytes(16));
  const cipherText = encrypt(payload, {
    version: contentEncoding,
    dh: userPublicKey,
    privateKey: localCurve,
    salt,
    authSecret: userAuth
  });
  return {
    localPublicKey,
    salt,
    cipherText
  };
};

// src/web-push-lib.ts
import { parse as parse2 } from "https://deno.land/std@0.146.0/node/url.ts";
import { encode as encode3 } from "https://esm.sh/urlsafe-base64@1.0.0?target=es2020";

// src/web-push-error.ts
import util from "https://deno.land/std@0.146.0/node/util.ts";
function WebPushError(message, statusCode, headers, body, endpoint) {
  Error.captureStackTrace(this, this.constructor);
  this.name = this.constructor.name;
  this.message = message;
  this.statusCode = statusCode;
  this.headers = headers;
  this.body = body;
  this.endpoint = endpoint;
}
util.inherits(WebPushError, Error);
var web_push_error_default = WebPushError;

// src/web-push-lib.ts
var DEFAULT_TTL = 2419200;
var gcmAPIKey = "";
var vapidDetails;
function WebPushLib() {
}
WebPushLib.prototype.setGCMAPIKey = function(apiKey) {
  if (apiKey === null) {
    gcmAPIKey = null;
    return;
  }
  if (typeof apiKey === "undefined" || typeof apiKey !== "string" || apiKey.length === 0) {
    throw new Error("The GCM API Key should be a non-empty string or null.");
  }
  gcmAPIKey = apiKey;
};
WebPushLib.prototype.setVapidDetails = function(subject, publicKey, privateKey) {
  if (arguments.length === 1 && arguments[0] === null) {
    vapidDetails = null;
    return;
  }
  validateSubject(subject);
  validatePublicKey(publicKey);
  validatePrivateKey(privateKey);
  vapidDetails = {
    subject,
    publicKey,
    privateKey
  };
};
WebPushLib.prototype.generateRequestDetails = function(subscription, payload, options) {
  if (!subscription || !subscription.endpoint) {
    throw new Error("You must pass in a subscription with at least an endpoint.");
  }
  if (typeof subscription.endpoint !== "string" || subscription.endpoint.length === 0) {
    throw new Error("The subscription endpoint must be a string with a valid URL.");
  }
  if (payload) {
    if (typeof subscription !== "object" || !subscription.keys || !subscription.keys.p256dh || !subscription.keys.auth) {
      throw new Error("To send a message with a payload, the subscription must have 'auth' and 'p256dh' keys.");
    }
  }
  let currentGCMAPIKey = gcmAPIKey;
  let currentVapidDetails = vapidDetails;
  let timeToLive = DEFAULT_TTL;
  let extraHeaders = {};
  let contentEncoding = web_push_constants_default.supportedContentEncodings.AES_128_GCM;
  let proxy;
  let agent;
  let timeout;
  if (options) {
    const validOptionKeys = [
      "headers",
      "gcmAPIKey",
      "vapidDetails",
      "TTL",
      "contentEncoding",
      "proxy",
      "agent",
      "timeout"
    ];
    const optionKeys = Object.keys(options);
    for (let i = 0; i < optionKeys.length; i += 1) {
      const optionKey = optionKeys[i];
      if (validOptionKeys.indexOf(optionKey) === -1) {
        throw new Error("'" + optionKey + "' is an invalid option. The valid options are ['" + validOptionKeys.join("', '") + "'].");
      }
    }
    if (options.headers) {
      extraHeaders = options.headers;
      let duplicates = Object.keys(extraHeaders).filter(function(header) {
        return typeof options[header] !== "undefined";
      });
      if (duplicates.length > 0) {
        throw new Error("Duplicated headers defined [" + duplicates.join(",") + "]. Please either define the header in thetop level options OR in the 'headers' key.");
      }
    }
    if (options.gcmAPIKey) {
      currentGCMAPIKey = options.gcmAPIKey;
    }
    if (options.vapidDetails !== void 0) {
      currentVapidDetails = options.vapidDetails;
    }
    if (options.TTL !== void 0) {
      timeToLive = Number(options.TTL);
      if (timeToLive < 0) {
        throw new Error("TTL should be a number and should be at least 0");
      }
    }
    if (options.contentEncoding) {
      if (options.contentEncoding === web_push_constants_default.supportedContentEncodings.AES_128_GCM || options.contentEncoding === web_push_constants_default.supportedContentEncodings.AES_GCM) {
        contentEncoding = options.contentEncoding;
      } else {
        throw new Error("Unsupported content encoding specified.");
      }
    }
    if (options.proxy) {
      if (typeof options.proxy === "string" || typeof options.proxy.host === "string") {
        proxy = options.proxy;
      } else {
        console.warn("Attempt to use proxy option, but invalid type it should be a string or proxy options object.");
      }
    }
    if (typeof options.timeout === "number") {
      timeout = options.timeout;
    }
  }
  if (typeof timeToLive === "undefined") {
    timeToLive = DEFAULT_TTL;
  }
  const requestDetails = {
    method: "POST",
    headers: {
      TTL: timeToLive
    }
  };
  Object.keys(extraHeaders).forEach(function(header) {
    requestDetails.headers[header] = extraHeaders[header];
  });
  let requestPayload = null;
  if (payload) {
    const encrypted = encrypt2(subscription.keys.p256dh, subscription.keys.auth, payload, contentEncoding);
    requestDetails.headers["Content-Length"] = encrypted.cipherText.length;
    requestDetails.headers["Content-Type"] = "application/octet-stream";
    if (contentEncoding === web_push_constants_default.supportedContentEncodings.AES_128_GCM) {
      requestDetails.headers["Content-Encoding"] = web_push_constants_default.supportedContentEncodings.AES_128_GCM;
    } else if (contentEncoding === web_push_constants_default.supportedContentEncodings.AES_GCM) {
      requestDetails.headers["Content-Encoding"] = web_push_constants_default.supportedContentEncodings.AES_GCM;
      requestDetails.headers.Encryption = "salt=" + encrypted.salt;
      requestDetails.headers["Crypto-Key"] = "dh=" + encode3(encrypted.localPublicKey);
    }
    requestPayload = encrypted.cipherText;
  } else {
    requestDetails.headers["Content-Length"] = 0;
  }
  const isGCM = subscription.endpoint.indexOf("https://android.googleapis.com/gcm/send") === 0;
  const isFCM = subscription.endpoint.indexOf("https://fcm.googleapis.com/fcm/send") === 0;
  if (isGCM) {
    if (!currentGCMAPIKey) {
      console.warn("Attempt to send push notification to GCM endpoint, but no GCM key is defined. Please use setGCMApiKey() or add 'gcmAPIKey' as an option.");
    } else {
      requestDetails.headers.Authorization = "key=" + currentGCMAPIKey;
    }
  } else if (currentVapidDetails) {
    const parsedUrl = parse2(subscription.endpoint, false, false);
    const audience = parsedUrl.protocol + "//" + parsedUrl.host;
    const vapidHeaders = getVapidHeaders(audience, currentVapidDetails.subject, currentVapidDetails.publicKey, currentVapidDetails.privateKey, contentEncoding);
    requestDetails.headers.Authorization = vapidHeaders.Authorization;
    if (contentEncoding === web_push_constants_default.supportedContentEncodings.AES_GCM) {
      if (requestDetails.headers["Crypto-Key"]) {
        requestDetails.headers["Crypto-Key"] += ";" + vapidHeaders["Crypto-Key"];
      } else {
        requestDetails.headers["Crypto-Key"] = vapidHeaders["Crypto-Key"];
      }
    }
  } else if (isFCM && currentGCMAPIKey) {
    requestDetails.headers.Authorization = "key=" + currentGCMAPIKey;
  }
  requestDetails.body = requestPayload;
  requestDetails.endpoint = subscription.endpoint;
  if (proxy) {
    requestDetails.proxy = proxy;
  }
  if (agent) {
    requestDetails.agent = agent;
  }
  if (timeout) {
    requestDetails.timeout = timeout;
  }
  return requestDetails;
};
WebPushLib.prototype.sendNotification = async function(subscription, payload, options) {
  let requestDetails;
  try {
    requestDetails = await this.generateRequestDetails(subscription, payload, options);
  } catch (err) {
    return Promise.reject(err);
  }
  return new Promise(async function(resolve, reject) {
    const httpsOptions = {};
    const urlParts = parse2(requestDetails.endpoint, false, false);
    httpsOptions.hostname = urlParts.hostname;
    httpsOptions.port = urlParts.port;
    httpsOptions.path = urlParts.path;
    httpsOptions.headers = requestDetails.headers;
    httpsOptions.method = requestDetails.method;
    if (requestDetails.timeout) {
      httpsOptions.timeout = requestDetails.timeout;
    }
    if (requestDetails.agent) {
      httpsOptions.agent = requestDetails.agent;
    }
    if (requestDetails.body) {
      httpsOptions.body = requestDetails.body;
    }
    const pushResponse = await fetch(requestDetails.endpoint, httpsOptions).catch((e) => {
      reject(e);
    });
    const responseText = await pushResponse.text();
    if (pushResponse.status < 200 || pushResponse.status > 299) {
      reject(new web_push_error_default("Received unexpected response code", pushResponse.status, pushResponse.headers, responseText, requestDetails.endpoint));
    } else {
      resolve({
        status: pushResponse.status,
        body: responseText,
        headers: pushResponse.headers
      });
    }
  });
};
var web_push_lib_default = WebPushLib;

// src/index.ts
var webPush = new web_push_lib_default();
var setGCMAPIKey = webPush.setGCMAPIKey;
var setVapidDetails = webPush.setVapidDetails;
var generateRequestDetails = webPush.generateRequestDetails;
var sendNotification = webPush.sendNotification;
export {
  web_push_error_default as WebPushError,
  encrypt2 as encrypt,
  generateRequestDetails,
  generateVAPIDKeys,
  getVapidHeaders,
  sendNotification,
  setGCMAPIKey,
  setVapidDetails,
  supportedContentEncodings
};
