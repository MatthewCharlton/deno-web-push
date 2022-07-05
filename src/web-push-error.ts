'use strict';

import util from 'https://deno.land/std@0.146.0/node/util.ts'

function WebPushError(this: any, message, statusCode, headers, body, endpoint) {
  Error.captureStackTrace(this, this.constructor);

  this.name = this.constructor.name;
  this.message = message;
  this.statusCode = statusCode;
  this.headers = headers;
  this.body = body;
  this.endpoint = endpoint;
}

util.inherits(WebPushError, Error);

export default WebPushError;
