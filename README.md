# sunasty-qr-payload

Zero-dependency JavaScript and TypeScript parser for structured QR code payloads (`WIFI:`, `otpauth://totp/`, `BEGIN:VCARD`, `mailto:`, `MATMSG:`, `smsto:`, `sms:`, `tel:`, and HTTP/HTTPS URLs with security inspection) paired with a Web Crypto `SubtleCrypto` RFC 6238 TOTP generator and RFC 4180 CSV/JSON serializers.

Extracted from the core engine powering the [Sunasty QR Scanner](https://sunasty.com/qr-scan/) and [Sunasty QR Code Generator](https://sunasty.com/qr-code/).

## Features

- **Structured QR Payload Parser**: `parseQrPayload` normalizes raw QR strings into a strongly typed discriminated union (`wifi`, `totp`, `vcard`, `email`, `sms`, `phone`, `url`, `text`).
- **RFC 6238 TOTP Generator**: `generateTotpCode` computes 6-digit (or N-digit) HMAC-SHA1 time-based one-time passwords using the standard Web Crypto `SubtleCrypto` API in Node.js (>= 18), browsers, and Service Workers.
- **URL Security Inspection**: `analyzeUrlSecurity` detects unencrypted `http://` links and raw IPv4/IPv6 hostnames before navigation.
- **Low-Contrast Image Preprocessors**: `applyHighContrastThreshold` and `normalizeAndBinarizeLowContrast` prepare RGBA buffers for QR matrix detection.
- **Batch History Export**: `serializeScanHistoryToCsv` (RFC 4180 compliant) and `serializeScanHistoryToJson`.

## Installation

Via npm:

```bash
npm install sunasty-qr-payload
```

Or import directly in browsers and Deno via ESM CDN (jsDelivr):

```js
import {
  parseQrPayload,
  generateTotpCode,
  analyzeUrlSecurity,
} from 'https://cdn.jsdelivr.net/gh/bsulyan/sunasty-qr-payload@1.0.0/index.js';
```

## Usage

### Parsing Structured QR Payloads

```js
import { parseQrPayload } from 'sunasty-qr-payload';

const wifi = parseQrPayload('WIFI:S:ProdNetwork;T:WPA2;P:SecretKey2026;H:false;;');
// { kind: 'wifi', ssid: 'ProdNetwork', encryption: 'WPA2', password: 'SecretKey2026', hidden: false }

const vcard = parseQrPayload(
  'BEGIN:VCARD\nVERSION:3.0\nFN:Alex Martin\nORG:Sunasty\nTEL:+33123456789\nEMAIL:alex@sunasty.com\nEND:VCARD'
);
// { kind: 'vcard', fullName: 'Alex Martin', org: 'Sunasty', phone: '+33123456789', email: 'alex@sunasty.com', ... }

const urlInfo = parseQrPayload('http://192.168.1.1/login');
// { kind: 'url', domain: '192.168.1.1', isInsecureHttp: true, isRawIp: true, hasSecurityWarning: true, ... }
```

### Generating RFC 6238 2FA TOTP Codes

```js
import { parseQrPayload, generateTotpCode } from 'sunasty-qr-payload';

const parsed = parseQrPayload(
  'otpauth://totp/Sunasty:ops@sunasty.com?secret=JBSWY3DPEHPK3PXP&issuer=Sunasty'
);

if (parsed.kind === 'totp') {
  const { code, remainingSeconds } = await generateTotpCode(
    parsed.secret,
    Date.now(),
    parsed.period,
    parsed.digits
  );
  console.log(`Current 2FA code: ${code} (valid for ${remainingSeconds}s)`);
}
```

### Exporting Scan History to RFC 4180 CSV

```js
import { serializeScanHistoryToCsv } from 'sunasty-qr-payload';

const csv = serializeScanHistoryToCsv([
  {
    timestamp: '2026-10-22T12:00:00.000Z',
    source: 'camera',
    type: 'url',
    isUrl: true,
    data: 'https://sunasty.com/qr-scan/',
  },
]);
```

## Web Utilities

- Client-side QR code scanner from image or webcam: [https://sunasty.com/qr-scan/](https://sunasty.com/qr-scan/)
- Custom SVG and PNG QR code generator: [https://sunasty.com/qr-code/](https://sunasty.com/qr-code/)
- Chrome/Chromium MV3 extension repository: [https://github.com/bsulyan/sunasty-qr-scanner](https://github.com/bsulyan/sunasty-qr-scanner)

## License

MIT
