export declare const SCAN_ACCEPTED_MIME: string[];
export declare const SCAN_MAX_BYTES: number;

export interface UrlSecurityAnalysis {
  valid: boolean;
  href: string;
  protocol: string;
  domain: string;
  pathAndQuery: string;
  isInsecureHttp: boolean;
  isRawIp: boolean;
  hasSecurityWarning: boolean;
}

export interface WifiPayload {
  kind: 'wifi';
  ssid: string;
  encryption: string;
  password: string;
  hidden: boolean;
}

export interface VcardPayload {
  kind: 'vcard';
  fullName: string;
  phone: string;
  email: string;
  org: string;
  rawVcard: string;
}

export interface EmailPayload {
  kind: 'email';
  to: string;
  subject: string;
  body: string;
  mailtoHref: string;
}

export interface SmsPayload {
  kind: 'sms';
  number: string;
  message: string;
  smsHref: string;
}

export interface PhonePayload {
  kind: 'phone';
  number: string;
  telHref: string;
}

export interface TotpPayload {
  kind: 'totp';
  label: string;
  account: string;
  issuer: string;
  secret: string;
  digits: number;
  period: number;
}

export interface UrlPayload extends UrlSecurityAnalysis {
  kind: 'url';
  text: string;
}

export interface TextPayload {
  kind: 'text';
  text: string;
}

export type ParsedQrPayload =
  | WifiPayload
  | VcardPayload
  | EmailPayload
  | SmsPayload
  | PhonePayload
  | TotpPayload
  | UrlPayload
  | TextPayload;

export interface TotpResult {
  code: string;
  remainingSeconds: number;
  period: number;
  counter: number;
}

export interface ScanRecord {
  timestamp?: string;
  source?: string;
  type?: string;
  isUrl?: boolean;
  data: string;
  [key: string]: unknown;
}

export declare function isAcceptedScanMime(mime: string): boolean;
export declare function looksLikeUrl(data: string): boolean;
export declare function analyzeUrlSecurity(rawUrl: string): UrlSecurityAnalysis;
export declare function parseQrPayload(data: string): ParsedQrPayload;
export declare function decodeBase32(base32: string): Uint8Array;
export declare function generateTotpCode(
  secretBase32: string,
  timestampMs?: number,
  period?: number,
  digits?: number
): Promise<TotpResult>;
export declare function applyHighContrastThreshold(
  data: Uint8ClampedArray,
  threshold?: number,
  invert?: boolean
): Uint8ClampedArray;
export declare function normalizeAndBinarizeLowContrast(
  data: Uint8ClampedArray
): Uint8ClampedArray;
export declare function serializeScanHistoryToCsv(results: ScanRecord[]): string;
export declare function serializeScanHistoryToJson(results: Array<Record<string, unknown>>): string;
export declare function truncateForDisplay(data: string, maxLen?: number): string;
