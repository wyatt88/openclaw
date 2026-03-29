/**
 * Federation Crypto — Ed25519 identity, signing, verification
 *
 * Reuses OpenClaw's existing device-identity infrastructure.
 * Every federation instance has an Ed25519 keypair:
 *   - Private key: never leaves the machine
 *   - Public key hash (SHA-256): serves as the peer ID ("address")
 *   - All messages are signed for non-repudiation
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";
import type {
  CapabilityGrant,
  FederationLocalIdentity,
  SignedMessage,
  FederationMessagePayload,
} from "./types.js";

// ─── Key Management ─────────────────────────────────────────

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function base64UrlEncode(buf: Buffer): string {
  return buf.toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/g, "");
}

function base64UrlDecode(input: string): Buffer {
  const normalized = input.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

function derivePublicKeyRaw(publicKeyPem: string): Buffer {
  const key = crypto.createPublicKey(publicKeyPem);
  const spki = key.export({ type: "spki", format: "der" }) as Buffer;
  if (
    spki.length === ED25519_SPKI_PREFIX.length + 32 &&
    spki.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    return spki.subarray(ED25519_SPKI_PREFIX.length);
  }
  return spki;
}

function fingerprintPublicKey(publicKeyPem: string): string {
  const raw = derivePublicKeyRaw(publicKeyPem);
  return crypto.createHash("sha256").update(raw).digest("hex");
}

/**
 * Resolve the federation identity file path.
 */
function resolveFederationIdentityPath(): string {
  return path.join(resolveStateDir(), "federation", "identity.json");
}

/**
 * Load or create the federation identity (Ed25519 keypair).
 * The identity file is stored with 0o600 permissions (owner-only).
 */
export function loadOrCreateFederationIdentity(
  name: string,
  filePath?: string,
): FederationLocalIdentity {
  const identityPath = filePath ?? resolveFederationIdentityPath();

  // Try to load existing identity
  try {
    if (fs.existsSync(identityPath)) {
      const raw = fs.readFileSync(identityPath, "utf8");
      const stored = JSON.parse(raw) as {
        version: number;
        peerId: string;
        name: string;
        publicKeyPem: string;
        privateKeyPem: string;
      };
      if (
        stored?.version === 1 &&
        typeof stored.publicKeyPem === "string" &&
        typeof stored.privateKeyPem === "string"
      ) {
        return {
          peerId: fingerprintPublicKey(stored.publicKeyPem),
          name: stored.name || name,
          publicKeyPem: stored.publicKeyPem,
          privateKeyPem: stored.privateKeyPem,
        };
      }
    }
  } catch {
    // Fall through to generate new identity
  }

  // Generate new Ed25519 keypair
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const peerId = fingerprintPublicKey(publicKeyPem);

  const identity: FederationLocalIdentity = {
    peerId,
    name,
    publicKeyPem,
    privateKeyPem,
  };

  // Persist with restricted permissions
  fs.mkdirSync(path.dirname(identityPath), { recursive: true });
  const stored = {
    version: 1,
    peerId,
    name,
    publicKeyPem,
    privateKeyPem,
    createdAtMs: Date.now(),
  };
  fs.writeFileSync(identityPath, `${JSON.stringify(stored, null, 2)}\n`, { mode: 0o600 });
  try {
    fs.chmodSync(identityPath, 0o600);
  } catch {
    // best-effort
  }

  return identity;
}

// ─── Signing ────────────────────────────────────────────────

/**
 * Sign a payload string with the local private key.
 * Returns base64url-encoded Ed25519 signature.
 */
export function signPayload(privateKeyPem: string, payload: string): string {
  const key = crypto.createPrivateKey(privateKeyPem);
  const sig = crypto.sign(null, Buffer.from(payload, "utf8"), key);
  return base64UrlEncode(sig);
}

/**
 * Verify a signature against a public key.
 */
export function verifySignature(
  publicKeyPem: string,
  payload: string,
  signatureBase64Url: string,
): boolean {
  try {
    const key = publicKeyPem.includes("BEGIN")
      ? crypto.createPublicKey(publicKeyPem)
      : crypto.createPublicKey({
          key: Buffer.concat([ED25519_SPKI_PREFIX, base64UrlDecode(publicKeyPem)]),
          type: "spki",
          format: "der",
        });
    const sig = base64UrlDecode(signatureBase64Url);
    return crypto.verify(null, Buffer.from(payload, "utf8"), key, sig);
  } catch {
    return false;
  }
}

/**
 * Generate a cryptographic challenge (32 random bytes, hex).
 */
export function generateChallenge(): string {
  return crypto.randomBytes(32).toString("hex");
}

// ─── Message Signing ────────────────────────────────────────

let messageSeq = 0;

/**
 * Create a signed federation message.
 */
export function createSignedMessage(
  identity: FederationLocalIdentity,
  message: FederationMessagePayload,
): SignedMessage {
  const payload = JSON.stringify(message);
  const seq = ++messageSeq;
  const timestamp = Date.now();

  // Sign: payload + seq + timestamp (prevents replay)
  const signData = `${payload}|${seq}|${timestamp}`;
  const signature = signPayload(identity.privateKeyPem, signData);

  return {
    payload,
    signature,
    senderId: identity.peerId,
    seq,
    timestamp,
  };
}

/**
 * Verify a signed federation message.
 */
export function verifySignedMessage(
  publicKeyPem: string,
  message: SignedMessage,
): { valid: boolean; payload?: FederationMessagePayload; error?: string } {
  // Check timestamp (reject messages older than 5 minutes)
  const age = Date.now() - message.timestamp;
  if (age > 5 * 60 * 1000) {
    return { valid: false, error: "Message expired (>5 minutes old)" };
  }
  if (age < -60 * 1000) {
    return { valid: false, error: "Message from the future (clock skew >1 minute)" };
  }

  // Verify signature
  const signData = `${message.payload}|${message.seq}|${message.timestamp}`;
  if (!verifySignature(publicKeyPem, signData, message.signature)) {
    return { valid: false, error: "Invalid signature" };
  }

  // Parse payload
  try {
    const payload = JSON.parse(message.payload) as FederationMessagePayload;
    return { valid: true, payload };
  } catch {
    return { valid: false, error: "Invalid payload JSON" };
  }
}

// ─── Capability Grant Signing ───────────────────────────────

/**
 * Create and sign a capability grant.
 */
export function createCapabilityGrant(
  identity: FederationLocalIdentity,
  params: Omit<CapabilityGrant, "signature" | "issuedAt" | "grantor">,
): CapabilityGrant {
  const grant: Omit<CapabilityGrant, "signature"> = {
    grantor: identity.peerId,
    grantee: params.grantee,
    capabilities: params.capabilities,
    rateLimit: params.rateLimit,
    expiresAt: params.expiresAt,
    issuedAt: Date.now(),
  };

  const payload = JSON.stringify(grant);
  const signature = signPayload(identity.privateKeyPem, payload);

  return { ...grant, signature };
}

/**
 * Verify a capability grant's signature.
 */
export function verifyCapabilityGrant(
  grantorPublicKeyPem: string,
  grant: CapabilityGrant,
): boolean {
  const { signature, ...rest } = grant;
  const payload = JSON.stringify(rest);
  return verifySignature(grantorPublicKeyPem, payload, signature);
}

/**
 * Check if a capability grant has expired.
 */
export function isCapabilityGrantExpired(grant: CapabilityGrant): boolean {
  if (!grant.expiresAt || grant.expiresAt === 0) return false;
  return Date.now() > grant.expiresAt;
}

/**
 * Check if a grant allows a specific capability.
 */
export function hasCapability(
  grant: CapabilityGrant | undefined,
  capability: string,
): boolean {
  if (!grant) return false;
  if (isCapabilityGrantExpired(grant)) return false;
  return grant.capabilities.includes(capability as any);
}

// ─── Peer ID Formatting ─────────────────────────────────────

/**
 * Format a peer ID for display (short form).
 * "a7f3bc9d1e2f..." → "oc1_a7f3...1e2f"
 */
export function formatPeerId(peerId: string): string {
  if (peerId.length < 16) return `oc1_${peerId}`;
  return `oc1_${peerId.slice(0, 4)}...${peerId.slice(-4)}`;
}

/**
 * Derive a peer ID from a public key (PEM or base64url).
 */
export function derivePeerIdFromPublicKey(publicKey: string): string | null {
  try {
    const raw = publicKey.includes("BEGIN")
      ? derivePublicKeyRaw(publicKey)
      : base64UrlDecode(publicKey);
    if (raw.length === 0) return null;
    return crypto.createHash("sha256").update(raw).digest("hex");
  } catch {
    return null;
  }
}
