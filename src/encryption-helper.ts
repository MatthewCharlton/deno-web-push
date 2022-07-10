'use strict';

import cryptoHelpers from './crypto.ts';
import { Buffer } from 'https://deno.land/std@0.147.0/node/buffer.ts';
import * as ece from './ece.ts';
import * as urlBase64 from 'https://esm.sh/urlsafe-base64@1.0.0?target=es2020';

export const encrypt = function (
  userPublicKey: string,
  userAuth: string,
  payload: string | Buffer,
  contentEncoding: any
) {
  if (!userPublicKey) {
    throw new Error('No user public key provided for encryption.');
  }

  if (typeof userPublicKey !== 'string') {
    throw new Error('The subscription p256dh value must be a string.');
  }

  if (urlBase64.decode(userPublicKey).length !== 65) {
    throw new Error('The subscription p256dh value should be 65 bytes long.');
  }

  if (!userAuth) {
    throw new Error('No user auth provided for encryption.');
  }

  if (typeof userAuth !== 'string') {
    throw new Error('The subscription auth key must be a string.');
  }

  if (urlBase64.decode(userAuth).length < 16) {
    throw new Error(
      'The subscription auth key should be at least 16 ' + 'bytes long'
    );
  }

  // console.log(
  //   'payload',
  //   payload,
  //   payload instanceof Uint8Array,
  //   Buffer.isBuffer(payload)
  // );

  if (payload instanceof Uint8Array) {
    payload = Buffer(payload);
  }

  if (typeof payload !== 'string' && !Buffer.isBuffer(payload)) {
    throw new Error('Payload must be either a string or a Node Buffer.');
  }

  if (typeof payload === 'string' || payload instanceof String) {
    payload = Buffer.from(payload);
  }

  const localCurve = cryptoHelpers.createECDH('prime256v1');
  const localPublicKey: Buffer = localCurve.generateKeys();

  const salt: string = urlBase64.encode(cryptoHelpers.randomBytes(16));

  const cipherText = ece.encrypt(payload, {
    version: contentEncoding,
    dh: userPublicKey,
    privateKey: localCurve,
    salt: salt,
    authSecret: userAuth,
  });

  return {
    localPublicKey: localPublicKey,
    salt: salt,
    cipherText: cipherText,
  };
};
