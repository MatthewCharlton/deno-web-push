'use strict';

const WebPushConstants: {
  supportedContentEncodings?: typeof supportedContentEncodings;
} = {};

export const supportedContentEncodings = {
  AES_GCM: 'aesgcm',
  AES_128_GCM: 'aes128gcm',
};

WebPushConstants.supportedContentEncodings = supportedContentEncodings;

export default WebPushConstants;
