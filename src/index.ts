'use strict';

export { getVapidHeaders, generateVAPIDKeys } from './vapid-helper.ts';
export { encrypt } from './encryption-helper.ts';
export { supportedContentEncodings } from './web-push-constants.ts';
import WebPushLib from './web-push-lib.ts';
import WebPushError from './web-push-error.ts';

const webPush = new WebPushLib();

export { WebPushError };
export const setGCMAPIKey = webPush.setGCMAPIKey;
export const setVapidDetails = webPush.setVapidDetails;
export const generateRequestDetails = webPush.generateRequestDetails;
export const sendNotification = webPush.sendNotification;
