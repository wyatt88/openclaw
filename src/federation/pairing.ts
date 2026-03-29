/**
 * Federation Peer Pairing — Establish trust between OpenClaw instances
 *
 * Two pairing methods:
 *   A) QR Code / Setup Code — offline exchange (like Bluetooth pairing)
 *   B) Tailscale auto-discovery — mDNS on the same tailnet
 *
 * Flow (Method A):
 *   1. Instance A: `openclaw federation pair --generate`
 *      → Generates 6-digit setup code + displays QR + starts pairing server
 *      → Waits up to 60s for incoming pairing request
 *
 *   2. Instance B: `openclaw federation pair --code ABCDEF`
 *      → Sends own public key + setup code to Instance A's pairing endpoint
 *      → If code matches, A responds with its public key
 *      → Both sides store each other's identity in the trust store
 *
 * Flow (Method B — Tailscale):
 *   1. Instances broadcast `_openclaw-federation._tcp` via mDNS
 *   2. Discovered peers prompt the owner for trust confirmation
 *   3. If accepted, challenge-response handshake + mutual key exchange
 *
 * Security:
 *   - Setup codes are single-use, time-limited (60s), and bound to a session
 *   - All key exchanges are signed with Ed25519
 *   - Pairing endpoints are ephemeral (torn down after pairing completes)
 *   - Challenge-response prevents replay attacks
 */

import * as crypto from "node:crypto";
import { EventEmitter } from "node:events";
import * as fs from "node:fs";
import * as path from "node:path";
import { resolveStateDir } from "../config/paths.js";
import {
  derivePeerIdFromPublicKey,
  signPayload,
  verifySignature,
  createCapabilityGrant,
  formatPeerId,
  generateChallenge,
} from "./crypto.js";
import { TrustStore } from "./trust-store.js";
import type {
  FederationLocalIdentity,
  FederationIdentity,
  PeerEndpoint,
  CapabilityGrant,
  FederationCapability,
} from "./types.js";

// ─── Pairing Code (OC- format) ─────────────────────────────

/**
 * Data embedded in an OC- pairing code.
 * Contains everything the acceptor needs to initiate a connection.
 */
export type PairingCodeData = {
  /** Ed25519 public key (base64). */
  publicKey: string;
  /** Initiator's federation endpoint (wss:// URL). */
  endpoint: string;
  /** One-time challenge for anti-replay. */
  challenge: string;
  /** Expiration timestamp (ms since epoch). */
  expiresAt: number;
  /** Instance name. */
  instanceName?: string;
};

/**
 * Encode pairing data into an OC- prefixed, dash-segmented code.
 *
 * Format: `OC-xxxx-xxxx-...-xxxx`
 *   1. JSON.stringify(PairingCodeData)
 *   2. base64url encode (using only [A-Za-z0-9_] — no `-` to avoid delimiter collision)
 *   3. Split every 4 chars, join with `-`
 *   4. Prefix `OC-`
 */
export function encodePairingCode(data: PairingCodeData): string {
  const json = JSON.stringify(data);
  // base64url with `-` replaced by `.` to avoid collision with segment delimiter
  const b64 = Buffer.from(json, "utf8")
    .toString("base64")
    .replaceAll("+", ".")
    .replaceAll("/", "_")
    .replace(/=+$/g, "");
  // Segment every 4 characters
  const segments: string[] = [];
  for (let i = 0; i < b64.length; i += 4) {
    segments.push(b64.slice(i, i + 4));
  }
  return `OC-${segments.join("-")}`;
}

/**
 * Decode an OC- pairing code back into {@link PairingCodeData}.
 *
 * Returns `null` if the code is malformed or unparseable.
 */
export function decodePairingCode(code: string): PairingCodeData | null {
  try {
    // Strip OC- prefix
    let raw = code.trim();
    if (!raw.startsWith("OC-")) {
      return null;
    }
    raw = raw.slice(3);

    // Remove segment dashes to reconstruct the encoded string
    const encoded = raw.replaceAll("-", "");

    // Reverse our custom encoding: `.` → `+`, `_` → `/`
    const b64 = encoded.replace(/\./g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json = Buffer.from(padded, "base64").toString("utf8");

    const data = JSON.parse(json) as PairingCodeData;

    // Minimal validation
    if (
      typeof data.publicKey !== "string" ||
      typeof data.endpoint !== "string" ||
      typeof data.challenge !== "string" ||
      typeof data.expiresAt !== "number"
    ) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

// ─── Types ──────────────────────────────────────────────────

export type PairingSessionState =
  | "waiting" // Generated code, waiting for peer
  | "received" // Received pairing request, awaiting owner confirmation
  | "confirmed" // Owner confirmed, exchanging keys
  | "completed" // Pairing successful
  | "expired" // Timeout
  | "rejected" // Owner rejected
  | "failed"; // Error

export type PairingSession = {
  /** Unique session identifier */
  sessionId: string;
  /** 6-digit alphanumeric setup code */
  setupCode: string;
  /** Challenge nonce for this session */
  challenge: string;
  /** Our identity (for display / exchange) */
  localIdentity: FederationLocalIdentity;
  /** Remote peer identity (set after initiate) */
  remoteIdentity?: FederationIdentity;
  /** Remote peer endpoint (set after initiate) */
  remoteEndpoint?: PeerEndpoint;
  /** Current state */
  state: PairingSessionState;
  /** When the session was created */
  createdAt: number;
  /** Timeout in ms */
  timeoutMs: number;
  /** Default capabilities to grant */
  defaultCapabilities: FederationCapability[];
};

/** Payload sent by the initiating peer (Instance B → A) */
export type PairingInitiatePayload = {
  /** The setup code entered by the user */
  setupCode: string;
  /** Initiator's public identity */
  identity: FederationIdentity;
  /** Initiator's endpoint */
  endpoint: PeerEndpoint;
  /** Challenge response: sign(setupCode + sessionId) */
  challengeResponse: string;
  /** Initiator's own challenge for the acceptor */
  challenge: string;
  /** Timestamp */
  timestamp: number;
};

/** Response from the accepting peer (Instance A → B) */
export type PairingAcceptPayload = {
  /** Acceptor's public identity */
  identity: FederationIdentity;
  /** Acceptor's endpoint */
  endpoint: PeerEndpoint;
  /** Signed challenge from the initiator */
  challengeResponse: string;
  /** Capability grant from acceptor to initiator */
  grant: CapabilityGrant;
  /** Timestamp */
  timestamp: number;
};

/** Final confirmation (Instance B → A) */
export type PairingConfirmPayload = {
  /** Initiator's peerId */
  peerId: string;
  /** Capability grant from initiator to acceptor */
  grant: CapabilityGrant;
  /** Timestamp */
  timestamp: number;
};

/** Result of a successful pairing */
export type PairingResult = {
  peerId: string;
  peerName: string;
  peerIdentity: FederationIdentity;
  peerEndpoint: PeerEndpoint;
  grantedCapabilities: FederationCapability[];
};

/** Tailscale discovery peer advertisement */
export type TailscaleDiscoveryRecord = {
  hostname: string;
  port: number;
  peerId: string;
  instanceName: string;
  publicKeyBase64: string;
  protocolVersion: number;
};

// ─── Setup Code Generation ──────────────────────────────────

const SETUP_CODE_LENGTH = 6;
const SETUP_CODE_CHARSET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // No 0/O/I/1 to avoid confusion

/**
 * Generate a human-friendly 6-character setup code.
 * Uses characters that are unambiguous when read aloud.
 */
export function generateSetupCode(): string {
  const bytes = crypto.randomBytes(SETUP_CODE_LENGTH);
  let code = "";
  for (let i = 0; i < SETUP_CODE_LENGTH; i++) {
    code += SETUP_CODE_CHARSET[bytes[i] % SETUP_CODE_CHARSET.length];
  }
  return code;
}

/**
 * Normalize setup code input (trim, uppercase, remove dashes/spaces).
 */
export function normalizeSetupCode(input: string): string {
  return input.trim().toUpperCase().replace(/[\s-]/g, "");
}

// ─── QR Code Data ───────────────────────────────────────────

export type PairingQrData = {
  /** Protocol identifier */
  proto: "openclaw-federation-pair";
  /** Protocol version */
  v: number;
  /** Setup code */
  code: string;
  /** Base64-encoded public key (raw 32 bytes) */
  pubkey: string;
  /** HTTP endpoint for pairing handshake */
  endpoint: string;
  /** Instance name */
  name: string;
};

/**
 * Generate QR code data string for pairing.
 */
export function generateQrPayload(params: {
  setupCode: string;
  publicKeyPem: string;
  endpoint: string;
  instanceName: string;
}): string {
  const data: PairingQrData = {
    proto: "openclaw-federation-pair",
    v: 1,
    code: params.setupCode,
    pubkey: extractBase64PublicKey(params.publicKeyPem),
    endpoint: params.endpoint,
    name: params.instanceName,
  };
  return JSON.stringify(data);
}

/**
 * Parse QR code data back into pairing info.
 */
export function parseQrPayload(raw: string): PairingQrData | null {
  try {
    const data = JSON.parse(raw) as PairingQrData;
    if (data.proto !== "openclaw-federation-pair") {
      return null;
    }
    if (typeof data.code !== "string" || typeof data.pubkey !== "string") {
      return null;
    }
    return data;
  } catch {
    return null;
  }
}

/**
 * Extract the raw 32-byte public key as base64 from PEM.
 */
function extractBase64PublicKey(publicKeyPem: string): string {
  const key = crypto.createPublicKey(publicKeyPem);
  const spki = key.export({ type: "spki", format: "der" }) as Buffer;
  // Ed25519 SPKI is 44 bytes: 12 bytes prefix + 32 bytes key
  const raw = spki.length > 32 ? spki.subarray(spki.length - 32) : spki;
  return raw.toString("base64");
}

// ─── Pairing Manager ────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 60_000;
const DEFAULT_CAPABILITIES: FederationCapability[] = ["chat"];

/**
 * PairingManager handles the lifecycle of pairing sessions.
 * Emits events for CLI/UI integration.
 *
 * Events:
 *   "session:created"   — New pairing session generated
 *   "session:received"  — Incoming pairing request received
 *   "session:confirmed" — Owner confirmed pairing
 *   "session:completed" — Pairing successful
 *   "session:expired"   — Session timed out
 *   "session:rejected"  — Owner rejected pairing
 *   "session:failed"    — Pairing failed (error)
 *   "discovery:found"   — Tailscale peer discovered
 */
export class PairingManager extends EventEmitter {
  private readonly identity: FederationLocalIdentity;
  private readonly trustStore: TrustStore;
  private activeSessions: Map<string, PairingSession> = new Map();
  private sessionTimers: Map<string, ReturnType<typeof setTimeout>> = new Map();
  /** Pending OC- pairing codes keyed by challenge nonce (in-memory cache). */
  private pendingPairingCodes: Map<string, PairingCodeData> = new Map();
  /** File path for persisting pending pairing codes (shared between CLI and Gateway). */
  private readonly pendingCodesPath: string;

  constructor(params: { identity: FederationLocalIdentity; trustStore: TrustStore }) {
    super();
    this.identity = params.identity;
    this.trustStore = params.trustStore;
    this.pendingCodesPath = path.join(
      resolveStateDir(),
      "federation",
      "pending-pairing-codes.json",
    );
  }

  // ─── Pending Code Persistence ─────────────────────────

  /** Load pending codes from disk, merging with in-memory state. */
  private loadPendingCodes(): void {
    try {
      if (!fs.existsSync(this.pendingCodesPath)) {
        return;
      }
      const raw = fs.readFileSync(this.pendingCodesPath, "utf8");
      const stored = JSON.parse(raw) as Record<string, PairingCodeData>;
      const now = Date.now();
      for (const [challenge, data] of Object.entries(stored)) {
        // Skip expired codes
        if (now > data.expiresAt) {
          continue;
        }
        // Don't overwrite in-memory entries
        if (!this.pendingPairingCodes.has(challenge)) {
          this.pendingPairingCodes.set(challenge, data);
        }
      }
    } catch {
      // Ignore read errors — start with in-memory state only
    }
  }

  /** Save all non-expired pending codes to disk. */
  private savePendingCodes(): void {
    try {
      const dir = path.dirname(this.pendingCodesPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const now = Date.now();
      const stored: Record<string, PairingCodeData> = {};
      for (const [challenge, data] of this.pendingPairingCodes) {
        if (now <= data.expiresAt) {
          stored[challenge] = data;
        }
      }
      fs.writeFileSync(this.pendingCodesPath, JSON.stringify(stored, null, 2), "utf8");
    } catch {
      // Non-fatal — codes still work in-memory for same process
    }
  }

  // ─── Method A: Setup Code Pairing ─────────────────────

  /**
   * Generate a new pairing session (Instance A).
   * Returns the session with setup code for display.
   */
  generatePairingSession(params?: {
    timeoutMs?: number;
    capabilities?: FederationCapability[];
  }): PairingSession {
    const sessionId = crypto.randomUUID();
    const setupCode = generateSetupCode();
    const challenge = generateChallenge();
    const timeoutMs = params?.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    const session: PairingSession = {
      sessionId,
      setupCode,
      challenge,
      localIdentity: this.identity,
      state: "waiting",
      createdAt: Date.now(),
      timeoutMs,
      defaultCapabilities: params?.capabilities ?? [...DEFAULT_CAPABILITIES],
    };

    this.activeSessions.set(sessionId, session);

    // Set expiry timer
    const timer = setTimeout(() => {
      this.expireSession(sessionId);
    }, timeoutMs);
    this.sessionTimers.set(sessionId, timer);

    this.emit("session:created", session);
    return session;
  }

  /**
   * Find an active session by setup code (called when a pairing request arrives).
   */
  findSessionByCode(setupCode: string): PairingSession | null {
    const normalized = normalizeSetupCode(setupCode);
    const sessions = Array.from(this.activeSessions.values());
    for (const session of sessions) {
      if (session.state === "waiting" && session.setupCode === normalized) {
        return session;
      }
    }
    return null;
  }

  /**
   * Handle an incoming pairing initiation (Instance A receives from B).
   * Validates the setup code and stores the remote identity.
   */
  handlePairingInitiate(
    sessionId: string,
    payload: PairingInitiatePayload,
  ): { ok: true; session: PairingSession } | { ok: false; error: string } {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      return { ok: false, error: "Session not found or expired" };
    }
    if (session.state !== "waiting") {
      return { ok: false, error: `Invalid session state: ${session.state}` };
    }

    // Validate setup code
    if (normalizeSetupCode(payload.setupCode) !== session.setupCode) {
      return { ok: false, error: "Invalid setup code" };
    }

    // Validate timestamp (reject stale requests)
    const age = Date.now() - payload.timestamp;
    if (Math.abs(age) > 5 * 60 * 1000) {
      return { ok: false, error: "Timestamp out of range (>5 min skew)" };
    }

    // Verify the challenge response: initiator signed (setupCode + sessionId)
    const expectedSignData = `${session.setupCode}|${session.sessionId}`;
    if (
      !verifySignature(payload.identity.publicKeyPem, expectedSignData, payload.challengeResponse)
    ) {
      return { ok: false, error: "Invalid challenge response signature" };
    }

    // Verify peerId matches public key
    const derivedPeerId = derivePeerIdFromPublicKey(payload.identity.publicKeyPem);
    if (derivedPeerId !== payload.identity.peerId) {
      return { ok: false, error: "Peer ID does not match public key" };
    }

    // Check if already trusted
    const existing = this.trustStore.getPeer(payload.identity.peerId);
    if (existing?.trust === "direct") {
      return {
        ok: false,
        error: `Peer ${formatPeerId(payload.identity.peerId)} is already trusted`,
      };
    }

    // Store remote identity and update state
    session.remoteIdentity = payload.identity;
    session.remoteEndpoint = payload.endpoint;
    session.challenge = payload.challenge; // Store initiator's challenge for our response
    session.state = "received";

    this.emit("session:received", session);
    return { ok: true, session };
  }

  /**
   * Accept a pairing request (Instance A owner confirms).
   * Returns the accept payload to send back to Instance B.
   */
  acceptPairing(
    sessionId: string,
    params?: { capabilities?: FederationCapability[] },
  ): { ok: true; payload: PairingAcceptPayload } | { ok: false; error: string } {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      return { ok: false, error: "Session not found or expired" };
    }
    if (session.state !== "received") {
      return { ok: false, error: `Invalid session state: ${session.state}` };
    }
    if (!session.remoteIdentity) {
      return { ok: false, error: "No remote identity in session" };
    }

    const capabilities = params?.capabilities ?? session.defaultCapabilities;

    // Sign the initiator's challenge (proves we are who we claim)
    const challengeResponse = signPayload(this.identity.privateKeyPem, session.challenge);

    // Create capability grant for the peer
    const grant = createCapabilityGrant(this.identity, {
      grantee: session.remoteIdentity.peerId,
      capabilities,
    });

    session.state = "confirmed";

    const payload: PairingAcceptPayload = {
      identity: {
        peerId: this.identity.peerId,
        publicKeyPem: this.identity.publicKeyPem,
        name: this.identity.name,
      },
      endpoint: this.getLocalEndpoint(),
      challengeResponse,
      grant,
      timestamp: Date.now(),
    };

    this.emit("session:confirmed", session);
    return { ok: true, payload };
  }

  /**
   * Handle the final confirmation from Instance B.
   * Stores the peer in the trust store.
   */
  handlePairingConfirm(
    sessionId: string,
    payload: PairingConfirmPayload,
  ): { ok: true; result: PairingResult } | { ok: false; error: string } {
    const session = this.activeSessions.get(sessionId);
    if (!session) {
      return { ok: false, error: "Session not found or expired" };
    }
    if (session.state !== "confirmed") {
      return { ok: false, error: `Invalid session state: ${session.state}` };
    }
    if (!session.remoteIdentity || !session.remoteEndpoint) {
      return { ok: false, error: "Missing remote identity or endpoint" };
    }

    // Verify the confirm comes from the right peer
    if (payload.peerId !== session.remoteIdentity.peerId) {
      return { ok: false, error: "Peer ID mismatch in confirm" };
    }

    // Store peer in trust store
    try {
      this.trustStore.addDirectPeer({
        identity: session.remoteIdentity,
        endpoint: session.remoteEndpoint,
        grant: payload.grant,
      });
    } catch (err) {
      return {
        ok: false,
        error: `Failed to store peer: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    // Also store the received capabilities
    this.trustStore.setReceivedCapabilities(session.remoteIdentity.peerId, payload.grant);

    session.state = "completed";
    this.cleanupSession(sessionId);

    const result: PairingResult = {
      peerId: session.remoteIdentity.peerId,
      peerName: session.remoteIdentity.name,
      peerIdentity: session.remoteIdentity,
      peerEndpoint: session.remoteEndpoint,
      grantedCapabilities: session.defaultCapabilities,
    };

    this.emit("session:completed", result);
    return { ok: true, result };
  }

  /**
   * Reject a pending pairing request (Instance A owner declines).
   */
  rejectPairing(sessionId: string): boolean {
    const session = this.activeSessions.get(sessionId);
    if (!session || session.state !== "received") {
      return false;
    }

    session.state = "rejected";
    this.cleanupSession(sessionId);
    this.emit("session:rejected", session);
    return true;
  }

  // ─── Initiator Side (Instance B) ─────────────────────

  /**
   * Create a pairing initiate payload for Instance B.
   * This is sent to Instance A's pairing endpoint.
   */
  createInitiatePayload(params: {
    setupCode: string;
    targetSessionId: string;
    localEndpoint: PeerEndpoint;
  }): PairingInitiatePayload {
    const challenge = generateChallenge();
    const signData = `${normalizeSetupCode(params.setupCode)}|${params.targetSessionId}`;
    const challengeResponse = signPayload(this.identity.privateKeyPem, signData);

    return {
      setupCode: normalizeSetupCode(params.setupCode),
      identity: {
        peerId: this.identity.peerId,
        publicKeyPem: this.identity.publicKeyPem,
        name: this.identity.name,
      },
      endpoint: params.localEndpoint,
      challengeResponse,
      challenge,
      timestamp: Date.now(),
    };
  }

  /**
   * Handle the accept response from Instance A (Instance B processes it).
   * Validates A's response and stores the peer.
   */
  handleAcceptResponse(
    initiateChallenge: string,
    payload: PairingAcceptPayload,
  ): { ok: true; result: PairingResult } | { ok: false; error: string } {
    // Verify timestamp
    const age = Date.now() - payload.timestamp;
    if (Math.abs(age) > 5 * 60 * 1000) {
      return { ok: false, error: "Timestamp out of range" };
    }

    // Verify peerId matches public key
    const derivedPeerId = derivePeerIdFromPublicKey(payload.identity.publicKeyPem);
    if (derivedPeerId !== payload.identity.peerId) {
      return { ok: false, error: "Peer ID does not match public key" };
    }

    // Verify challenge response (proves the acceptor has the private key)
    if (
      !verifySignature(payload.identity.publicKeyPem, initiateChallenge, payload.challengeResponse)
    ) {
      return { ok: false, error: "Invalid challenge response from acceptor" };
    }

    // Store peer in trust store
    try {
      this.trustStore.addDirectPeer({
        identity: payload.identity,
        endpoint: payload.endpoint,
        grant: payload.grant,
      });
    } catch (err) {
      return {
        ok: false,
        error: `Failed to store peer: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    const result: PairingResult = {
      peerId: payload.identity.peerId,
      peerName: payload.identity.name,
      peerIdentity: payload.identity,
      peerEndpoint: payload.endpoint,
      grantedCapabilities: payload.grant.capabilities,
    };

    return { ok: true, result };
  }

  /**
   * Create a confirm payload (Instance B → A, final step).
   */
  createConfirmPayload(params: {
    targetPeerId: string;
    capabilities?: FederationCapability[];
  }): PairingConfirmPayload {
    const grant = createCapabilityGrant(this.identity, {
      grantee: params.targetPeerId,
      capabilities: params.capabilities ?? [...DEFAULT_CAPABILITIES],
    });

    return {
      peerId: this.identity.peerId,
      grant,
      timestamp: Date.now(),
    };
  }

  // ─── Method C: OC- Code Pairing (Endpoint-based) ──────

  /**
   * Generate a pairing code that embeds our endpoint + public key.
   * The recipient can pair by just entering this code + their own endpoint.
   */
  generatePairingCode(params: { endpoint: string; expiresInMs?: number }): {
    code: string;
    data: PairingCodeData;
  } {
    const challenge = generateChallenge();
    const expiresAt = Date.now() + (params.expiresInMs ?? 5 * 60 * 1000);

    const data: PairingCodeData = {
      publicKey: extractBase64PublicKey(this.identity.publicKeyPem),
      endpoint: params.endpoint,
      challenge,
      expiresAt,
      instanceName: this.identity.name,
    };

    // Store pending code so handleCodeAcceptRequest can verify it later
    this.pendingPairingCodes.set(challenge, data);
    this.savePendingCodes();

    // Auto-cleanup when code expires
    setTimeout(
      () => {
        this.pendingPairingCodes.delete(challenge);
        this.savePendingCodes();
      },
      expiresAt - Date.now() + 1000,
    );

    return { code: encodePairingCode(data), data };
  }

  /**
   * Handle an incoming code-accept request from a peer that decoded our OC- code.
   *
   * Called by the Gateway HTTP server when POST /federation/pair/code-accept arrives.
   *
   * Flow:
   *   1. Verify the challengeResponse matches a pending code's challenge
   *   2. Verify the peer's identity (peerId matches publicKey)
   *   3. Sign the peer's challenge (prove our identity)
   *   4. Store the peer in trust store
   *   5. Return our identity + challengeResponse + grant
   */
  handleCodeAcceptRequest(payload: {
    identity: FederationIdentity;
    endpoint: PeerEndpoint;
    challengeResponse: string;
    challenge: string;
    timestamp: number;
  }):
    | {
        ok: true;
        identity: FederationIdentity;
        endpoint: PeerEndpoint;
        challengeResponse: string;
        grant: CapabilityGrant;
      }
    | { ok: false; error: string } {
    // Validate timestamp (reject stale requests)
    const age = Date.now() - payload.timestamp;
    if (Math.abs(age) > 5 * 60 * 1000) {
      return { ok: false, error: "Timestamp out of range (>5 min skew)" };
    }

    // Verify peerId matches public key
    const derivedPeerId = derivePeerIdFromPublicKey(payload.identity.publicKeyPem);
    if (derivedPeerId !== payload.identity.peerId) {
      return { ok: false, error: "Peer ID does not match public key" };
    }

    // Load pending codes from disk (may have been created by CLI in another process)
    this.loadPendingCodes();

    // Find the pending code by verifying challengeResponse against each pending challenge
    let matchedChallenge: string | null = null;
    for (const [challenge, codeData] of this.pendingPairingCodes) {
      // Check expiry
      if (Date.now() > codeData.expiresAt) {
        this.pendingPairingCodes.delete(challenge);
        continue;
      }
      // Verify the peer signed our challenge correctly
      if (verifySignature(payload.identity.publicKeyPem, challenge, payload.challengeResponse)) {
        matchedChallenge = challenge;
        break;
      }
    }

    if (!matchedChallenge) {
      return { ok: false, error: "Invalid challenge response — no matching pairing code found" };
    }

    // Consume the pairing code (single-use)
    this.pendingPairingCodes.delete(matchedChallenge);
    this.savePendingCodes();

    // Check if already trusted
    const existing = this.trustStore.getPeer(payload.identity.peerId);
    if (existing?.trust === "direct") {
      return {
        ok: false,
        error: `Peer ${formatPeerId(payload.identity.peerId)} is already trusted`,
      };
    }

    // Sign the peer's challenge to prove our identity
    const challengeResponse = signPayload(this.identity.privateKeyPem, payload.challenge);

    // Create capability grant
    const grant = createCapabilityGrant(this.identity, {
      grantee: payload.identity.peerId,
      capabilities: [...DEFAULT_CAPABILITIES],
    });

    // Store peer in trust store
    try {
      this.trustStore.addDirectPeer({
        identity: payload.identity,
        endpoint: payload.endpoint,
        grant,
      });
    } catch (err) {
      return {
        ok: false,
        error: `Failed to store peer: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    const result: PairingResult = {
      peerId: payload.identity.peerId,
      peerName: payload.identity.name,
      peerIdentity: payload.identity,
      peerEndpoint: payload.endpoint,
      grantedCapabilities: grant.capabilities,
    };

    this.emit("session:completed", result);

    return {
      ok: true,
      identity: {
        peerId: this.identity.peerId,
        publicKeyPem: this.identity.publicKeyPem,
        name: this.identity.name,
      },
      endpoint: this.getLocalEndpoint(),
      challengeResponse,
      grant,
    };
  }

  /** Get the count of pending pairing codes. */
  get pendingCodeCount(): number {
    return this.pendingPairingCodes.size;
  }

  /**
   * Accept a pairing code and initiate connection to the remote peer.
   *
   * Flow:
   *   1. Decode pairing code → remote publicKey + endpoint
   *   2. Verify not expired
   *   3. Connect to remote endpoint, send our publicKey + endpoint + challenge response
   *   4. Both sides verify → mutual trust established
   *   5. Return PairingResult
   *
   * @param code - The OC-xxxx-xxxx pairing code
   * @param ourEndpoint - Our federation endpoint (wss:// URL)
   * @returns PairingResult on success
   */
  async acceptPairingCode(
    code: string,
    ourEndpoint: string,
  ): Promise<{ ok: true; result: PairingResult } | { ok: false; error: string }> {
    // 1. Decode the pairing code
    const data = decodePairingCode(code);
    if (!data) {
      return { ok: false, error: "Invalid pairing code format" };
    }

    // 2. Check expiration
    if (Date.now() > data.expiresAt) {
      return { ok: false, error: "Pairing code has expired" };
    }

    // 3. Build our challenge response (sign the remote challenge)
    const challengeResponse = signPayload(this.identity.privateKeyPem, data.challenge);
    const ourChallenge = generateChallenge();

    // 4. Send pairing request to the initiator's endpoint
    const pairingPayload = {
      identity: {
        peerId: this.identity.peerId,
        publicKeyPem: this.identity.publicKeyPem,
        name: this.identity.name,
      },
      endpoint: { wsUrl: ourEndpoint } as PeerEndpoint,
      challengeResponse,
      challenge: ourChallenge,
      timestamp: Date.now(),
    };

    let response: Response;
    try {
      // Derive HTTP URL from wss:// endpoint for pairing handshake
      const httpBase = data.endpoint
        .replace(/^wss:\/\//, "https://")
        .replace(/^ws:\/\//, "http://");
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 15_000);
      response = await fetch(`${httpBase}/federation/pair/code-accept`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(pairingPayload),
        signal: controller.signal,
      });
      clearTimeout(timer);
    } catch (err) {
      return {
        ok: false,
        error: `Cannot reach peer at ${data.endpoint}: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    if (!response.ok) {
      const body = (await response.json().catch(() => ({ error: "Unknown error" }))) as {
        error?: string;
      };
      return { ok: false, error: body.error ?? `HTTP ${response.status}` };
    }

    const body = (await response.json()) as {
      ok: boolean;
      identity?: FederationIdentity;
      endpoint?: PeerEndpoint;
      challengeResponse?: string;
      grant?: CapabilityGrant;
      error?: string;
    };

    if (!body.ok || !body.identity || !body.challengeResponse) {
      return { ok: false, error: body.error ?? "Invalid response from peer" };
    }

    // 5. Verify the peer's challenge response (they signed OUR challenge)
    if (!verifySignature(body.identity.publicKeyPem, ourChallenge, body.challengeResponse)) {
      return { ok: false, error: "Challenge verification failed — peer identity not verified" };
    }

    // Verify peer ID matches public key
    const derivedPeerId = derivePeerIdFromPublicKey(body.identity.publicKeyPem);
    if (derivedPeerId !== body.identity.peerId) {
      return { ok: false, error: "Peer ID does not match public key" };
    }

    // 6. Store the peer in trust store
    // Prefer endpoint from response, fall back to the one in the pairing code
    const bodyEndpoint = body.endpoint;
    const hasEndpoint = bodyEndpoint && (bodyEndpoint.wsUrl || bodyEndpoint.httpUrl);
    const peerEndpoint: PeerEndpoint = hasEndpoint ? bodyEndpoint : { wsUrl: data.endpoint };
    const grant =
      body.grant ??
      createCapabilityGrant(this.identity, {
        grantee: body.identity.peerId,
        capabilities: [...DEFAULT_CAPABILITIES],
      });

    try {
      this.trustStore.addDirectPeer({
        identity: body.identity,
        endpoint: peerEndpoint,
        grant,
      });
    } catch (err) {
      return {
        ok: false,
        error: `Failed to store peer: ${err instanceof Error ? err.message : String(err)}`,
      };
    }

    const result: PairingResult = {
      peerId: body.identity.peerId,
      peerName: body.identity.name,
      peerIdentity: body.identity,
      peerEndpoint: peerEndpoint,
      grantedCapabilities: grant.capabilities,
    };

    this.emit("session:completed", result);
    return { ok: true, result };
  }

  // ─── Method B: Tailscale Auto-Discovery ───────────────

  /**
   * Create a Tailscale mDNS advertisement record.
   */
  createDiscoveryRecord(port: number): TailscaleDiscoveryRecord {
    return {
      hostname: getLocalHostname(),
      port,
      peerId: this.identity.peerId,
      instanceName: this.identity.name,
      publicKeyBase64: extractBase64PublicKey(this.identity.publicKeyPem),
      protocolVersion: 1,
    };
  }

  /**
   * Handle a discovered peer from Tailscale mDNS.
   * Returns pairing info for owner confirmation prompt.
   */
  handleDiscoveredPeer(record: TailscaleDiscoveryRecord): {
    isNew: boolean;
    peerId: string;
    instanceName: string;
    hostname: string;
  } {
    const existing = this.trustStore.getPeer(record.peerId);
    this.emit("discovery:found", record);

    return {
      isNew: !existing,
      peerId: record.peerId,
      instanceName: record.instanceName,
      hostname: record.hostname,
    };
  }

  // ─── Session Management ───────────────────────────────

  getSession(sessionId: string): PairingSession | null {
    return this.activeSessions.get(sessionId) ?? null;
  }

  getActiveSessionCount(): number {
    return this.activeSessions.size;
  }

  private expireSession(sessionId: string): void {
    const session = this.activeSessions.get(sessionId);
    if (session && (session.state === "waiting" || session.state === "received")) {
      session.state = "expired";
      this.emit("session:expired", session);
      this.cleanupSession(sessionId);
    }
  }

  private cleanupSession(sessionId: string): void {
    const timer = this.sessionTimers.get(sessionId);
    if (timer) {
      clearTimeout(timer);
      this.sessionTimers.delete(sessionId);
    }
    this.activeSessions.delete(sessionId);
  }

  /**
   * Cancel all active sessions (cleanup on shutdown).
   */
  cancelAll(): void {
    for (const timer of Array.from(this.sessionTimers.values())) {
      clearTimeout(timer);
    }
    this.sessionTimers.clear();
    this.activeSessions.clear();
    this.pendingPairingCodes.clear();
    this.savePendingCodes();
  }

  // ─── Helpers ──────────────────────────────────────────

  private getLocalEndpoint(): PeerEndpoint {
    const hostname = getLocalHostname();
    // Read endpoint from federation config
    const configEndpoint = this.readEndpointFromConfig();
    return {
      wsUrl: configEndpoint || undefined,
      tailnetHostname: hostname.endsWith(".ts.net") ? hostname : undefined,
    };
  }

  /** Read federation.endpoint from openclaw.json config. */
  private readEndpointFromConfig(): string | undefined {
    try {
      const home =
        process.env.OPENCLAW_HOME ??
        path.join(process.env.HOME ?? process.env.USERPROFILE ?? ".", ".openclaw");
      const configPath = process.env.OPENCLAW_CONFIG_PATH ?? path.join(home, "openclaw.json");
      const raw = JSON.parse(fs.readFileSync(configPath, "utf8")) as {
        federation?: { endpoint?: string };
      };
      return raw.federation?.endpoint;
    } catch {
      return undefined;
    }
  }
}

// ─── Utility Functions ──────────────────────────────────────

function getLocalHostname(): string {
  try {
    const os = require("node:os");
    return os.hostname();
  } catch {
    return "unknown";
  }
}

/**
 * Render a simple ASCII QR code representation for terminal display.
 * For actual QR code rendering, use the `qrcode-terminal` package.
 * This is a fallback that shows the pairing data as a compact string.
 */
export function renderPairingDisplay(params: {
  setupCode: string;
  peerId: string;
  instanceName: string;
  endpoint?: string;
}): string {
  const lines: string[] = [];
  lines.push("╔══════════════════════════════════════╗");
  lines.push("║     Federation Pairing Session       ║");
  lines.push("╠══════════════════════════════════════╣");
  lines.push("║                                      ║");
  lines.push(`║  Setup Code:  ${params.setupCode.padEnd(22)}║`);
  lines.push("║                                      ║");
  lines.push(`║  Instance:    ${params.instanceName.slice(0, 22).padEnd(22)}║`);
  lines.push(`║  Peer ID:     ${formatPeerId(params.peerId).padEnd(22)}║`);
  lines.push("║                                      ║");
  if (params.endpoint) {
    lines.push(`║  Endpoint:    ${params.endpoint.slice(0, 22).padEnd(22)}║`);
    lines.push("║                                      ║");
  }
  lines.push("║  Waiting for peer to connect...      ║");
  lines.push("║  (timeout: 60s)                      ║");
  lines.push("║                                      ║");
  lines.push("╚══════════════════════════════════════╝");
  return lines.join("\n");
}

/**
 * Format a pairing result for display.
 */
export function formatPairingResult(result: PairingResult): string {
  const lines: string[] = [];
  lines.push("✅ Pairing successful!");
  lines.push("");
  lines.push(`  Peer:         ${result.peerName}`);
  lines.push(`  Peer ID:      ${formatPeerId(result.peerId)}`);
  lines.push(`  Capabilities: ${result.grantedCapabilities.join(", ")}`);
  if (result.peerEndpoint.wsUrl) {
    lines.push(`  WebSocket:    ${result.peerEndpoint.wsUrl}`);
  }
  if (result.peerEndpoint.tailnetHostname) {
    lines.push(`  Tailnet:      ${result.peerEndpoint.tailnetHostname}`);
  }
  return lines.join("\n");
}
