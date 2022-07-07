'use strict';

import cryptoHelpers from './crypto.ts';
import { Buffer } from 'https://deno.land/std@0.141.0/node/buffer.ts';
import { parse } from 'https://deno.land/std@0.146.0/node/url.ts';
import { SignJWT } from 'https://deno.land/x/jose@v3.19.0/jwt/sign.ts';
import toPEM from 'https://deno.land/x/jose@v4.8.3/lib/format_pem.ts';
import {
  encode,
  validate,
  decode,
} from 'https://cdn.skypack.dev/urlsafe-base64';

import { supportedContentEncodings } from './web-push-constants.ts';

/**
 * DEFAULT_EXPIRATION is set to seconds in 12 hours
 */
const DEFAULT_EXPIRATION_SECONDS = 12 * 60 * 60;

// Maximum expiration is 24 hours according. (See VAPID spec)
const MAX_EXPIRATION_SECONDS = 24 * 60 * 60;

function generateVAPIDKeys() {
  const curve = cryptoHelpers.createECDH('prime256v1');
  curve.generateKeys();

  let publicKeyBuffer = curve.getPublicKey();
  let privateKeyBuffer = curve.getPrivateKey();

  // Occassionally the keys will not be padded to the correct lengh resulting
  // in errors, hence this padding.
  // See https://github.com/web-push-libs/web-push/issues/295 for history.
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
    privateKey: encode(privateKeyBuffer),
  };
}

function validateSubject(subject: string) {
  if (!subject) {
    throw new Error('No subject set in vapidDetails.subject.');
  }

  if (typeof subject !== 'string' || subject.length === 0) {
    throw new Error(
      'The subject value must be a string containing a URL or ' +
        'mailto: address. ' +
        subject
    );
  }

  if (subject.indexOf('mailto:') !== 0) {
    const subjectParseResult = parse(subject, false, false);
    if (!subjectParseResult.hostname) {
      throw new Error('Vapid subject is not a url or mailto url. ' + subject);
    }
  }
}

function validatePublicKey(publicKey: string) {
  if (!publicKey) {
    throw new Error('No key set vapidDetails.publicKey');
  }

  if (typeof publicKey !== 'string') {
    throw new Error(
      'Vapid public key is must be a URL safe Base 64 ' + 'encoded string.'
    );
  }

  if (!validate(publicKey)) {
    throw new Error(
      'Vapid public key must be a URL safe Base 64 (without "=")'
    );
  }

  publicKey = decode(publicKey);

  if (publicKey.length !== 65) {
    throw new Error('Vapid public key should be 65 bytes long when decoded.');
  }
}

function validatePrivateKey(privateKey: string) {
  if (!privateKey) {
    throw new Error('No key set in vapidDetails.privateKey');
  }

  if (typeof privateKey !== 'string') {
    throw new Error(
      'Vapid private key must be a URL safe Base 64 ' + 'encoded string.'
    );
  }

  if (!validate(privateKey)) {
    throw new Error(
      'Vapid private key must be a URL safe Base 64 (without "=")'
    );
  }

  privateKey = decode(privateKey);

  if (privateKey.length !== 32) {
    throw new Error('Vapid private key should be 32 bytes long when decoded.');
  }
}

/**
 * Given the number of seconds calculates
 * the expiration in the future by adding the passed `numSeconds`
 * with the current seconds from Unix Epoch
 *
 * @param {Number} numSeconds Number of seconds to be added
 * @return {Number} Future expiration in seconds
 */
function getFutureExpirationTimestamp(numSeconds: number) {
  const futureExp = new Date();
  futureExp.setSeconds(futureExp.getSeconds() + numSeconds);
  return Math.floor(futureExp.getTime() / 1000);
}

/**
 * Validates the Expiration Header based on the VAPID Spec
 * Throws error of type `Error` if the expiration is not validated
 *
 * @param {Number} expiration Expiration seconds from Epoch to be validated
 */
function validateExpiration(expiration: number) {
  if (!Number.isInteger(expiration)) {
    throw new Error('`expiration` value must be a number');
  }

  if (expiration < 0) {
    throw new Error('`expiration` must be a positive integer');
  }

  // Roughly checks the time of expiration, since the max expiration can be ahead
  // of the time than at the moment the expiration was generated
  const maxExpirationTimestamp = getFutureExpirationTimestamp(
    MAX_EXPIRATION_SECONDS
  );

  if (expiration >= maxExpirationTimestamp) {
    throw new Error('`expiration` value is greater than maximum of 24 hours');
  }
}

/**
 * This method takes the required VAPID parameters and returns the required
 * header to be added to a Web Push Protocol Request.
 * @param  {string} audience        This must be the origin of the push service.
 * @param  {string} subject         This should be a URL or a 'mailto:' email
 * address.
 * @param  {string} publicKey       The VAPID public key.
 * @param  {string} privateKey      The VAPID private key.
 * @param  {string} contentEncoding The contentEncoding type.
 * @param  {integer} [expiration]   The expiration of the VAPID JWT.
 * @return {Object}                 Returns an Object with the Authorization and
 * 'Crypto-Key' values to be used as headers.
 */
async function getVapidHeaders(
  audience: string,
  subject: string,
  publicKey: string,
  privateKey: string,
  contentEncoding: string,
  expiration?: number
): Promise<{ Authorization: string; 'Crypto-Key'?: string }> {
  if (!audience) {
    throw new Error('No audience could be generated for VAPID.');
  }

  if (typeof audience !== 'string' || audience.length === 0) {
    throw new Error(
      'The audience value must be a string containing the ' +
        'origin of a push service. ' +
        audience
    );
  }

  const audienceParseResult = parse(audience, false, false);
  if (!audienceParseResult.hostname) {
    throw new Error('VAPID audience is not a url. ' + audience);
  }

  validateSubject(subject);
  validatePublicKey(publicKey);
  validatePrivateKey(privateKey);

  const privateKeyBuffer = decode(privateKey);

  if (expiration) {
    validateExpiration(expiration);
  } else {
    expiration = getFutureExpirationTimestamp(DEFAULT_EXPIRATION_SECONDS);
  }

  const header = {
    typ: 'JWT',
    alg: 'ES256',
  };

  const jwtPayload = {
    aud: audience,
    exp: expiration,
    sub: subject,
  };

  console.log('privateKeyBuffer', privateKeyBuffer.toString('base64'));

  const privateKeyToSign = await globalThis.crypto.subtle.importKey(
    'pkcs8',
    privateKeyBuffer as unknown as ArrayBuffer,
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    true,
    ['sign']
  );

  // console.log('privateKeyToSign', privateKeyToSign);

  const jwt = new SignJWT(jwtPayload)
    .setProtectedHeader(header)
    .sign(privateKeyToSign);

  console.log('jwt', jwt);

  if (contentEncoding === supportedContentEncodings.AES_128_GCM) {
    return {
      Authorization: 'vapid t=' + jwt + ', k=' + publicKey,
    };
  }
  if (contentEncoding === supportedContentEncodings.AES_GCM) {
    return {
      Authorization: 'WebPush ' + jwt,
      'Crypto-Key': 'p256ecdsa=' + publicKey,
    };
  }

  throw new Error('Unsupported encoding type specified.');
}

export {
  generateVAPIDKeys,
  getFutureExpirationTimestamp,
  getVapidHeaders,
  validateSubject,
  validatePublicKey,
  validatePrivateKey,
  validateExpiration,
};
