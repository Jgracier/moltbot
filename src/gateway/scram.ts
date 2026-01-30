import crypto from "node:crypto";

const SCRAM_ITERATIONS = 32_768;
const SALT_BYTES = 16;
const NONCE_BYTES = 16;

function hi(password: string, salt: Buffer, iterations: number): Buffer {
  return crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");
}

function h(data: Buffer): Buffer {
  return crypto.createHash("sha256").update(data).digest();
}

function hmac(key: Buffer, data: string): Buffer {
  return crypto.createHmac("sha256", key).update(data, "utf8").digest();
}

function xor(a: Buffer, b: Buffer): Buffer {
  const out = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i]! ^ b[i]!;
  return out;
}

/**
 * Server: generate challenge from client's first message and the shared secret (token).
 * Returns serverFirst message and state to verify clientFinal later.
 */
export function generateChallenge(
  secret: string,
  clientFirst: string,
): {
  serverFirst: string;
  saltB64: string;
  iterations: number;
  state: ScramVerifyState;
} {
  const clientFirstBare = clientFirst.replace(/^.,,/, "");
  const clientNonceMatch = clientFirstBare.match(/r=([^,]+)/);
  const clientNonce = clientNonceMatch?.[1] ?? "";
  const serverNonce = crypto.randomBytes(NONCE_BYTES).toString("base64").replace(/=/g, "");
  const salt = crypto.randomBytes(SALT_BYTES);
  const saltB64 = salt.toString("base64");
  const iterations = SCRAM_ITERATIONS;

  const saltedPassword = hi(secret, salt, iterations);
  const clientKey = hmac(saltedPassword, "Client Key");
  const storedKey = h(clientKey);
  const serverKey = hmac(saltedPassword, "Server Key");

  const serverFirst = `r=${clientNonce}${serverNonce},s=${saltB64},i=${iterations}`;

  return {
    serverFirst,
    saltB64,
    iterations,
    state: {
      clientFirstBare,
      serverFirst,
      storedKey,
      serverKey,
      serverNonce: clientNonce + serverNonce,
    },
  };
}

export type ScramVerifyState = {
  clientFirstBare: string;
  serverFirst: string;
  storedKey: Buffer;
  serverKey: Buffer;
  serverNonce: string;
};

/**
 * Server: verify client's final message (proof). Returns true if valid.
 */
export function verifyClientProof(state: ScramVerifyState, clientFinal: string): boolean {
  const pMatch = clientFinal.match(/p=([^,]+)/);
  const rMatch = clientFinal.match(/r=([^,]+)/);
  const cMatch = clientFinal.match(/c=([^,]+)/);
  const proofB64 = pMatch?.[1];
  const r = rMatch?.[1];
  const c = cMatch?.[1];
  if (!proofB64 || !r || !c || r !== state.serverNonce) return false;

  const clientFinalWithoutProof = `c=${c},r=${r}`;
  const authMessage = `${state.clientFirstBare},${state.serverFirst},${clientFinalWithoutProof}`;
  const clientSignature = hmac(state.storedKey, authMessage);

  let clientKey: Buffer;
  try {
    const proof = Buffer.from(proofB64, "base64");
    clientKey = xor(proof, clientSignature);
  } catch {
    return false;
  }

  const storedKeyFromClient = h(clientKey);
  return storedKeyFromClient.equals(state.storedKey);
}

/**
 * Client: compute client_final message from secret, clientFirst, and challenge payload.
 */
export function computeClientProof(
  secret: string,
  clientFirst: string,
  serverFirst: string,
  saltB64: string,
  iterations: number,
): string {
  const clientFirstBare = clientFirst.replace(/^.,,/, "");
  const salt = Buffer.from(saltB64, "base64");
  const saltedPassword = hi(secret, salt, iterations);
  const clientKey = hmac(saltedPassword, "Client Key");
  const storedKey = h(clientKey);

  const rMatch = serverFirst.match(/r=([^,]+)/);
  const serverNonce = rMatch?.[1] ?? "";
  const c = Buffer.from("n,,", "utf8").toString("base64");
  const clientFinalWithoutProof = `c=${c},r=${serverNonce}`;
  const authMessage = `${clientFirstBare},${serverFirst},${clientFinalWithoutProof}`;
  const clientSignature = hmac(storedKey, authMessage);
  const clientProof = xor(clientKey, clientSignature);
  return `${clientFinalWithoutProof},p=${clientProof.toString("base64")}`;
}

/**
 * Client: build initial client_first message (no username, optional).
 */
export function buildClientFirst(): { clientFirst: string } {
  const nonce = crypto.randomBytes(NONCE_BYTES).toString("base64").replace(/=/g, "");
  const clientFirst = `n,,n=gateway,r=${nonce}`;
  return { clientFirst };
}
