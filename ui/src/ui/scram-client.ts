/**
 * Browser-side SCRAM-SHA-256 client (Web Crypto). Matches server protocol in src/gateway/scram.ts.
 */

function randomBase64Url(bytes: number): string {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode(...arr)).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function hi(password: string, salt: Uint8Array, iterations: number): Promise<ArrayBuffer> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  return crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    key,
    256,
  );
}

async function h(data: ArrayBuffer): Promise<ArrayBuffer> {
  return crypto.subtle.digest("SHA-256", data);
}

async function hmac(key: ArrayBuffer, data: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(data));
}

function xor(a: ArrayBuffer, b: ArrayBuffer): Uint8Array {
  const va = new Uint8Array(a);
  const vb = new Uint8Array(b);
  const out = new Uint8Array(va.length);
  for (let i = 0; i < va.length; i++) out[i] = va[i]! ^ vb[i]!;
  return out;
}

function arrayBufferToBase64(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export function buildClientFirst(): { clientFirst: string } {
  const nonce = randomBase64Url(16);
  const clientFirst = `n,,n=gateway,r=${nonce}`;
  return { clientFirst };
}

export async function computeClientProof(
  secret: string,
  clientFirst: string,
  serverFirst: string,
  saltB64: string,
  iterations: number,
): Promise<string> {
  const clientFirstBare = clientFirst.replace(/^.,,/, "");
  const saltStr = saltB64.includes("-") || saltB64.includes("_")
    ? saltB64.replace(/-/g, "+").replace(/_/g, "/")
    : saltB64;
  const salt = Uint8Array.from(atob(saltStr), (c) => c.charCodeAt(0));
  const saltedPassword = await hi(secret, salt, iterations);
  const clientKey = await hmac(saltedPassword, "Client Key");
  const storedKey = await h(clientKey);

  const rMatch = serverFirst.match(/r=([^,]+)/);
  const serverNonce = rMatch?.[1] ?? "";
  const c = btoa("n,,");
  const clientFinalWithoutProof = `c=${c},r=${serverNonce}`;
  const authMessage = `${clientFirstBare},${serverFirst},${clientFinalWithoutProof}`;
  const clientSignature = await hmac(storedKey, authMessage);
  const clientProof = xor(clientKey, clientSignature);
  return `${clientFinalWithoutProof},p=${arrayBufferToBase64(clientProof)}`;
}
