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

  constructor(params: { identity: FederationLocalIdentity; trustStore: TrustStore }) {
    super();
    this.identity = params.identity;
    this.trustStore = params.trustStore;
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
  }

  // ─── Helpers ──────────────────────────────────────────

  private getLocalEndpoint(): PeerEndpoint {
    const hostname = getLocalHostname();
    return {
      tailnetHostname: hostname.endsWith(".ts.net") ? hostname : undefined,
    };
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
