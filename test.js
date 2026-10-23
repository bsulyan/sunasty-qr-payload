import test from 'node:test';
import assert from 'node:assert/strict';

import {
  isAcceptedScanMime,
  looksLikeUrl,
  analyzeUrlSecurity,
  parseQrPayload,
  decodeBase32,
  generateTotpCode,
  applyHighContrastThreshold,
  normalizeAndBinarizeLowContrast,
  serializeScanHistoryToCsv,
  serializeScanHistoryToJson,
  truncateForDisplay,
} from './index.js';

test('MIME check and URL security analyzer', () => {
  assert.equal(isAcceptedScanMime('image/png'), true);
  assert.equal(isAcceptedScanMime('application/pdf'), false);
  assert.equal(looksLikeUrl('https://sunasty.com/qr-scan/'), true);
  assert.equal(looksLikeUrl('WIFI:S:Test;;'), false);

  const secure = analyzeUrlSecurity('https://sunasty.com/qr-scan/?ref=npm');
  assert.equal(secure.valid, true);
  assert.equal(secure.domain, 'sunasty.com');
  assert.equal(secure.isInsecureHttp, false);
  assert.equal(secure.isRawIp, false);
  assert.equal(secure.hasSecurityWarning, false);

  const insecureIp = analyzeUrlSecurity('http://192.168.1.1/admin');
  assert.equal(insecureIp.isInsecureHttp, true);
  assert.equal(insecureIp.isRawIp, true);
  assert.equal(insecureIp.hasSecurityWarning, true);
});

test('Structured QR payload parser across all URI schemes', () => {
  const wifi = parseQrPayload('WIFI:S:Office\\;Net;T:WPA2;P:Sec\\;ret!;H:true;;');
  assert.equal(wifi.kind, 'wifi');
  assert.equal(wifi.ssid, 'Office;Net');
  assert.equal(wifi.encryption, 'WPA2');
  assert.equal(wifi.password, 'Sec;ret!');
  assert.equal(wifi.hidden, true);

  const totp = parseQrPayload(
    'otpauth://totp/Sunasty:ops@sunasty.com?secret=JBSWY3DPEHPK3PXP&issuer=Sunasty&digits=6&period=30'
  );
  assert.equal(totp.kind, 'totp');
  assert.equal(totp.issuer, 'Sunasty');
  assert.equal(totp.account, 'ops@sunasty.com');
  assert.equal(totp.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(totp.digits, 6);
  assert.equal(totp.period, 30);

  const vcard = parseQrPayload(
    'BEGIN:VCARD\nVERSION:3.0\nFN:Jane Doe\nORG:Sunasty Engineering\nTEL:+33123456789\nEMAIL:jane@sunasty.com\nEND:VCARD'
  );
  assert.equal(vcard.kind, 'vcard');
  assert.equal(vcard.fullName, 'Jane Doe');
  assert.equal(vcard.org, 'Sunasty Engineering');
  assert.equal(vcard.phone, '+33123456789');
  assert.equal(vcard.email, 'jane@sunasty.com');

  const mailto = parseQrPayload('mailto:dev@sunasty.com?subject=Bug%20Report&body=Details');
  assert.equal(mailto.kind, 'email');
  assert.equal(mailto.to, 'dev@sunasty.com');
  assert.equal(mailto.subject, 'Bug Report');
  assert.equal(mailto.body, 'Details');

  const matmsg = parseQrPayload('MATMSG:TO:dev@sunasty.com;SUB:Inquiry;BODY:Hello;;');
  assert.equal(matmsg.kind, 'email');
  assert.equal(matmsg.to, 'dev@sunasty.com');
  assert.equal(matmsg.subject, 'Inquiry');
  assert.equal(matmsg.body, 'Hello');

  const smsto = parseQrPayload('smsto:+33600000000:Verification code');
  assert.equal(smsto.kind, 'sms');
  assert.equal(smsto.number, '+33600000000');
  assert.equal(smsto.message, 'Verification code');

  const tel = parseQrPayload('tel:+33102030405');
  assert.equal(tel.kind, 'phone');
  assert.equal(tel.number, '+33102030405');

  const plain = parseQrPayload('SN-9482-AC');
  assert.equal(plain.kind, 'text');
  assert.equal(plain.text, 'SN-9482-AC');
});

test('RFC 4648 Base32 decoding and RFC 6238 TOTP HMAC-SHA1 generation', async () => {
  const bytes = decodeBase32('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.equal(Buffer.from(bytes).toString('ascii'), '12345678901234567890');

  const rfcVector = await generateTotpCode('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59000, 30, 6);
  assert.equal(rfcVector.code, '287082');
  assert.equal(rfcVector.remainingSeconds, 1);

  const liveVector = await generateTotpCode('JBSWY3DPEHPK3PXP', 1700000000000, 30, 6);
  assert.match(liveVector.code, /^\d{6}$/);
});

test('Contrast thresholding and RFC 4180 CSV / JSON serialization', () => {
  const rgba = new Uint8ClampedArray([110, 110, 110, 255, 160, 160, 160, 255]);
  const bin = applyHighContrastThreshold(rgba, 128, false);
  assert.equal(bin[0], 0);
  assert.equal(bin[4], 255);

  const norm = normalizeAndBinarizeLowContrast(rgba);
  assert.equal(norm[0], 0);
  assert.equal(norm[4], 255);

  const records = [
    {
      timestamp: '2026-10-22T12:00:00.000Z',
      source: 'file',
      type: 'url',
      isUrl: true,
      data: 'https://sunasty.com/qr-scan/',
    },
  ];
  const csv = serializeScanHistoryToCsv(records);
  assert.ok(csv.includes('timestamp,source,type,isUrl,data'));
  assert.ok(csv.includes('https://sunasty.com/qr-scan/'));

  const json = JSON.parse(serializeScanHistoryToJson(records));
  assert.equal(json[0].data, 'https://sunasty.com/qr-scan/');
  assert.equal(truncateForDisplay('abcdef', 3), 'abc…');
});
