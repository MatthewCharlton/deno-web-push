'use strict';

const assert = require('assert');
const crypto = require('crypto');
const webPush = require('../index.js');
const ece = require('http_ece');
const urlBase64 = require('urlsafe-base64');

console.log('webPush',webPush);



const userCurve = crypto.createECDH('prime256v1');
const VALID_PUBLIC_KEY = urlBase64.encode(userCurve.generateKeys()).slice(0, 65);
const VALID_AUTH = urlBase64.encode(crypto.randomBytes(16));

console.log('VALID_PUBLIC_KEY',VALID_PUBLIC_KEY);
console.log('VALID_AUTH',VALID_AUTH);

function encryptDecrypt(thing, contentEncoding) {
  const encrypted = webPush.encrypt(VALID_PUBLIC_KEY, VALID_AUTH, thing, contentEncoding);

  return ece.decrypt(encrypted.cipherText, {
    version: contentEncoding,
    dh: urlBase64.encode(encrypted.localPublicKey),
    privateKey: userCurve,
    salt: encrypted.salt,
    authSecret: VALID_AUTH
  });
}

console.log("encryptDecrypt('hello', webPush.supportedContentEncodings.AES_GCM)", encryptDecrypt('hello', webPush.supportedContentEncodings.AES_GCM));

suite('Test Encryption Helpers', function() {
  test('is defined', function() {
    assert(webPush.encrypt);
  });



  test('encrypt/decrypt string (aesgcm)', function() {
    assert(encryptDecrypt('hello', webPush.supportedContentEncodings.AES_GCM).equals(Buffer.from('hello')));
  });

  test('encrypt/decrypt string (aes128gcm)', function() {
    assert(encryptDecrypt('hello', webPush.supportedContentEncodings.AES_128_GCM).equals(Buffer.from('hello')));
  });

  test('encrypt/decrypt buffer (aesgcm)', function() {
    assert(encryptDecrypt(Buffer.from('hello'), webPush.supportedContentEncodings.AES_GCM).equals(Buffer.from('hello')));
  });

  test('encrypt/decrypt buffer (aes128gcm)', function() {
    assert(encryptDecrypt(Buffer.from('hello'), webPush.supportedContentEncodings.AES_128_GCM).equals(Buffer.from('hello')));
  });

  // userPublicKey, userAuth, payload
  const badInputs = [
    function(contentEncoding) {
      webPush.encrypt(null, null, null, contentEncoding);
    },
    function(contentEncoding) {
      // Invalid public key
      webPush.encrypt(null, VALID_AUTH, 'Example', contentEncoding);
    },
    function(contentEncoding) {
      // Invalid auth
      webPush.encrypt(VALID_PUBLIC_KEY, null, 'Example', contentEncoding);
    },
    function(contentEncoding) {
      // No payload
      webPush.encrypt(VALID_PUBLIC_KEY, VALID_AUTH, null, contentEncoding);
    },
    function(contentEncoding) {
      // Invalid auth size
      webPush.encrypt(VALID_PUBLIC_KEY, 'Fake', 'Example', contentEncoding);
    },
    function(contentEncoding) {
      // Invalid auth size
      webPush.encrypt(VALID_PUBLIC_KEY, VALID_AUTH, [], contentEncoding);
    }
  ];

  function testBadInput(contentEncoding) {
    badInputs.forEach(function(badInput, index) {
      assert.throws(function() {
        badInput(contentEncoding);
        console.log('Encryption input failed to throw: ' + index);
      });
    });
  }

  test('bad input to encrypt (aesgcm)', function() {
    testBadInput(webPush.supportedContentEncodings.AES_GCM);
  });

  test('bad input to encrypt (aes128gcm)', function() {
    testBadInput(webPush.supportedContentEncodings.AES_128_GCM);
  });
});
