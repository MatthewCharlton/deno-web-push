'use strict';

import cryptoHelpers from './crypto.ts';
import { Buffer } from 'https://deno.land/std@0.147.0/node/buffer.ts';
import { parse } from 'https://deno.land/std@0.146.0/node/url.ts';
import * as jws from 'https://esm.sh/jws@4.0.0?target=es2020';
import asn1 from 'https://esm.sh/asn1.js@5.4.1?target=es2020';
import {
  encode,
  validate,
  decode,
} from 'https://esm.sh/urlsafe-base64@1.0.0?target=es2020';

import { supportedContentEncodings } from './web-push-constants.ts';

/**
 * DEFAULT_EXPIRATION is set to seconds in 12 hours
 */
const DEFAULT_EXPIRATION_SECONDS = 12 * 60 * 60;

// Maximum expiration is 24 hours according. (See VAPID spec)
const MAX_EXPIRATION_SECONDS = 24 * 60 * 60;

const ECPrivateKeyASN = asn1.define('ECPrivateKey', function () {
  this.seq().obj(
    this.key('version').int(),
    this.key('privateKey').octstr(),
    this.key('parameters').explicit(0).objid().optional(),
    this.key('publicKey').explicit(1).bitstr().optional()
  );
});

function toPEM(key) {
  return ECPrivateKeyASN.encode(
    {
      version: 1,
      privateKey: key,
      parameters: [1, 2, 840, 10045, 3, 1, 7], // prime256v1
    },
    'pem',
    {
      label: 'EC PRIVATE KEY',
    }
  );
}

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
function getVapidHeaders(
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

  const jwt = jws.sign({
    header: header,
    payload: jwtPayload,
    privateKey: toPEM(privateKey),
  });

  console.log('jwt', jwt);
  console.log('contentEncoding', contentEncoding);

  if (contentEncoding === supportedContentEncodings.AES_128_GCM) {
    console.log(
      JSON.stringify({
        Authorization: 'vapid t=' + jwt + ', k=' + publicKey,
      })
    );

    return {
      Authorization: 'vapid t=' + jwt + ', k=' + publicKey,
    };
  }
  if (contentEncoding === supportedContentEncodings.AES_GCM) {
    console.log(
      JSON.stringify({
        Authorization: 'WebPush ' + jwt,
        'Crypto-Key': 'p256ecdsa=' + publicKey,
      })
    );

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
