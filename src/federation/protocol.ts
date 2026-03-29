/**
 * Federation Wire Protocol — Message format, signing, validation, and handshake
 *
 * Defines the wire protocol for peer-to-peer communication between
 * federated OpenClaw instances. All messages are Ed25519-signed with
 * replay protection (timestamp + dedup) and mutual authentication
 * via a 3-step challenge-response handshake.
 *
 * @module federation/protocol
 */

import crypto from "node:crypto";
import { signPayload, verifySignature, generateChallenge } from "./crypto.js";
import { TrustStore } from "./trust-store.js";
import type { FederationLocalIdentity, TrustedPeer } from "./types.js";

// ─── Message Types ──────────────────────────────────────────

/**
 * Federation wire protocol message types.
 *
 * Covers the full lifecycle: handshake → heartbeat → application messages.
 */
export enum FederationMessageType {
  // Handshake (mutual authentication)
  HELLO = "hello",
  HELLO_ACK = "hello_ack",
  AUTH_COMPLETE = "auth_complete",

  // Heartbeat
  PING = "ping",
  PONG = "pong",

  // Chat (agent-to-agent)
  CHAT_MESSAGE = "chat_message",
  CHAT_RESPONSE = "chat_response",

  // Status
  STATUS_REQUEST = "status_request",
  STATUS_RESPONSE = "status_response",
}

// ─── Message Envelope ───────────────────────────────────────

/**
 * Wire-format message exchanged between federation peers.
 *
 * The `signature` covers `{ type, id, from, to, timestamp, payload }`
 * serialized as JSON (deterministic key order via explicit construction).
 */
export interface FederationMessage {
  /** Message type discriminator. */
  type: FederationMessageType;
  /** Unique message ID (UUID v4). */
  id: string;
  /** Sender peerId (SHA-256 of Ed25519 public key). */
  from: string;
  /** Target peerId. Omit for broadcast / handshake messages. */
  to?: string;
  /** Unix epoch milliseconds when the message was created. */
  timestamp: number;
  /** Ed25519 signature (base64url) of the canonical signing payload. */
  signature: string;
  /** Application-level payload (type-specific). */
  payload: unknown;
}

// ─── Handshake Payloads ─────────────────────────────────────

/** HELLO payload — sent by the initiator to start mutual auth. */
export interface HelloPayload {
  peerId: string;
  publicKey: string; // PEM
  challenge: string; // 32-byte hex
  instanceName: string;
}

/** HELLO_ACK payload — sent by the responder. */
export interface HelloAckPayload {
  peerId: string;
  publicKey: string; // PEM
  challengeResponse: string; // Signed challenge from HELLO
  challenge: string; // Responder's own challenge
}

/** AUTH_COMPLETE payload — sent by the initiator to finish handshake. */
export interface AuthCompletePayload {
  challengeResponse: string; // Signed counter-challenge
}

// ─── Constants ──────────────────────────────────────────────

/** Maximum allowed clock skew (ms) for incoming messages. */
const MAX_TIMESTAMP_DRIFT_MS = 5 * 60 * 1000; // 5 minutes

/** Size of the recent-message-ID dedup set. */
const DEDUP_SET_CAPACITY = 1000;

// ─── Helpers ────────────────────────────────────────────────

/**
 * Build the canonical string that gets signed / verified.
 *
 * Deterministic: keys are always in the same order.
 */
function buildSigningPayload(
  type: FederationMessageType,
  id: string,
  from: string,
  to: string | undefined,
  timestamp: number,
  payload: unknown,
): string {
  return JSON.stringify({ type, id, from, to, timestamp, payload });
}

/**
 * Generate a UUID v4 using Node's crypto module.
 */
function uuid(): string {
  return crypto.randomUUID();
}

// ─── Dedup Ring ─────────────────────────────────────────────

/**
 * Fixed-capacity set for detecting duplicate message IDs.
 *
 * Uses an internal array as a ring buffer so that the oldest entry
 * is evicted once capacity is reached — O(1) insert, O(n) lookup
 * which is fine for n ≤ 1000.
 */
class DedupRing {
  private readonly ids: string[] = [];
  private readonly seen = new Set<string>();
  private cursor = 0;

  constructor(private readonly capacity: number) {}

  /**
   * Returns `true` if `id` was already seen (duplicate).
   * Otherwise records it and returns `false`.
   */
  isDuplicate(id: string): boolean {
    if (this.seen.has(id)) {
      return true;
    }

    // Evict oldest if at capacity.
    if (this.ids.length >= this.capacity) {
      const evicted = this.ids[this.cursor];
      this.seen.delete(evicted);
      this.ids[this.cursor] = id;
    } else {
      this.ids.push(id);
    }
    this.seen.add(id);
    this.cursor = (this.cursor + 1) % this.capacity;
    return false;
  }

  /** Current number of tracked IDs. */
  get size(): number {
    return this.seen.size;
  }
}

// ─── Validation Result ──────────────────────────────────────

export type ValidateOk = { ok: true; message: FederationMessage };
export type ValidateFail = { ok: false; error: string };
export type ValidateResult = ValidateOk | ValidateFail;

// ─── MessageHandler ─────────────────────────────────────────

export type MessageHandlerOptions = {
  /** Local identity (includes private key for signing). */
  identity: FederationLocalIdentity;
  /** Trust store for looking up peer public keys. */
  trustStore: TrustStore;
  /** Override dedup capacity (default 1000). */
  dedupCapacity?: number;
  /** Override max timestamp drift in ms (default 300 000). */
  maxTimestampDriftMs?: number;
};

type Handler = (msg: FederationMessage) => void;

/**
 * Creates, signs, validates, and dispatches federation protocol messages.
 *
 * Thread-safe for single-threaded Node.js — no shared mutable state
 * across async boundaries (all mutations are synchronous).
 */
export class MessageHandler {
  private readonly identity: FederationLocalIdentity;
  private readonly trustStore: TrustStore;
  private readonly dedup: DedupRing;
  private readonly maxDrift: number;
  private readonly handlers = new Map<FederationMessageType, Handler[]>();

  constructor(opts: MessageHandlerOptions) {
    this.identity = opts.identity;
    this.trustStore = opts.trustStore;
    this.dedup = new DedupRing(opts.dedupCapacity ?? DEDUP_SET_CAPACITY);
    this.maxDrift = opts.maxTimestampDriftMs ?? MAX_TIMESTAMP_DRIFT_MS;
  }

  // ─── Create (sign) ───────────────────────────────────

  /**
   * Serialize and sign a new outbound message.
   *
   * @param type  - Message type.
   * @param payload - Type-specific payload.
   * @param to    - Optional target peerId.
   * @returns A fully-formed, signed {@link FederationMessage}.
   */
  createMessage(type: FederationMessageType, payload: unknown, to?: string): FederationMessage {
    const id = uuid();
    const from = this.identity.peerId;
    const timestamp = Date.now();

    const signingPayload = buildSigningPayload(type, id, from, to, timestamp, payload);
    const signature = signPayload(this.identity.privateKeyPem, signingPayload);

    // Track our own message ID so we don't re-process if echoed.
    this.dedup.isDuplicate(id);

    return { type, id, from, to, timestamp, signature, payload };
  }

  // ─── Validate (verify) ───────────────────────────────

  /**
   * Parse, verify, and validate an incoming raw JSON message.
   *
   * Checks performed (in order):
   * 1. JSON parse
   * 2. Structural / field-type validation
   * 3. Duplicate message ID
   * 4. Timestamp drift (±5 min)
   * 5. Sender lookup in trust store (for non-HELLO messages)
   * 6. Ed25519 signature verification
   *
   * For HELLO messages the public key is taken from the payload itself
   * (since the sender isn't in the trust store yet). The caller must
   * separately verify that the peerId matches the public key.
   *
   * @param raw - Raw JSON string from the wire.
   * @returns Validation result with the parsed message or an error string.
   */
  validateMessage(raw: string): ValidateResult {
    // 1. Parse
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { ok: false, error: "Invalid JSON" };
    }

    if (typeof parsed !== "object" || parsed === null) {
      return { ok: false, error: "Message must be a JSON object" };
    }

    const obj = parsed as Record<string, unknown>;

    // 2. Structural validation
    if (
      typeof obj.type !== "string" ||
      !Object.values(FederationMessageType).includes(obj.type as FederationMessageType)
    ) {
      return { ok: false, error: `Unknown message type: ${String(obj.type)}` };
    }
    if (typeof obj.id !== "string" || obj.id.length === 0) {
      return { ok: false, error: "Missing or invalid message id" };
    }
    if (typeof obj.from !== "string" || obj.from.length === 0) {
      return { ok: false, error: "Missing or invalid sender (from)" };
    }
    if (obj.to !== undefined && typeof obj.to !== "string") {
      return { ok: false, error: "Invalid recipient (to)" };
    }
    if (typeof obj.timestamp !== "number" || !Number.isFinite(obj.timestamp)) {
      return { ok: false, error: "Missing or invalid timestamp" };
    }
    if (typeof obj.signature !== "string" || obj.signature.length === 0) {
      return { ok: false, error: "Missing or invalid signature" };
    }

    const msg: FederationMessage = {
      type: obj.type as FederationMessageType,
      id: obj.id,
      from: obj.from,
      to: obj.to,
      timestamp: obj.timestamp,
      signature: obj.signature,
      payload: obj.payload,
    };

    // 3. Dedup
    if (this.dedup.isDuplicate(msg.id)) {
      return { ok: false, error: "Duplicate message id" };
    }

    // 4. Timestamp drift
    const drift = Math.abs(Date.now() - msg.timestamp);
    if (drift > this.maxDrift) {
      return {
        ok: false,
        error: `Timestamp drift too large: ${Math.round(drift / 1000)}s (max ${Math.round(this.maxDrift / 1000)}s)`,
      };
    }

    // 5. Resolve sender public key
    let publicKeyPem: string;

    if (msg.type === FederationMessageType.HELLO) {
      // For HELLO the sender isn't in our trust store yet.
      // Extract the public key from the payload itself.
      const helloPayload = msg.payload as Partial<HelloPayload> | null;
      if (
        !helloPayload ||
        typeof helloPayload.publicKey !== "string" ||
        !helloPayload.publicKey.includes("BEGIN PUBLIC KEY")
      ) {
        return { ok: false, error: "HELLO payload missing valid publicKey" };
      }
      publicKeyPem = helloPayload.publicKey;
    } else {
      const peer: TrustedPeer | undefined = this.trustStore.getPeer(msg.from);
      if (!peer) {
        return { ok: false, error: `Unknown sender: ${msg.from}` };
      }
      publicKeyPem = peer.identity.publicKeyPem;
    }

    // 6. Signature verification
    const signingPayload = buildSigningPayload(
      msg.type,
      msg.id,
      msg.from,
      msg.to,
      msg.timestamp,
      msg.payload,
    );
    const valid = verifySignature(publicKeyPem, signingPayload, msg.signature);
    if (!valid) {
      return { ok: false, error: "Invalid signature" };
    }

    return { ok: true, message: msg };
  }

  // ─── Event Dispatch ──────────────────────────────────

  /**
   * Register a handler for a specific message type.
   *
   * Multiple handlers may be registered per type; they are called
   * in registration order.
   */
  on(type: FederationMessageType, handler: Handler): void {
    let list = this.handlers.get(type);
    if (!list) {
      list = [];
      this.handlers.set(type, list);
    }
    list.push(handler);
  }

  /**
   * Remove a previously registered handler.
   */
  off(type: FederationMessageType, handler: Handler): void {
    const list = this.handlers.get(type);
    if (!list) {
      return;
    }
    const idx = list.indexOf(handler);
    if (idx !== -1) {
      list.splice(idx, 1);
    }
  }

  /**
   * Dispatch a validated message to all registered handlers for its type.
   */
  dispatch(msg: FederationMessage): void {
    const list = this.handlers.get(msg.type);
    if (!list) {
      return;
    }
    for (const handler of list) {
      handler(msg);
    }
  }
}

// ─── Handshake State ────────────────────────────────────────

export type HandshakePhase =
  | "idle"
  | "hello_sent" // Initiator: sent HELLO, waiting for HELLO_ACK
  | "hello_ack_sent" // Responder: sent HELLO_ACK, waiting for AUTH_COMPLETE
  | "authenticated"; // Both sides: handshake complete

export type PendingHandshakeState = {
  phase: HandshakePhase;
  /** Our challenge (initiator) or the peer's challenge (responder). */
  ourChallenge: string;
  /** Peer's challenge that we need to respond to (responder: in HELLO_ACK flow). */
  peerChallenge?: string;
  /** Peer's peerId once known. */
  peerId?: string;
  /** Peer's public key PEM (from HELLO payload). */
  peerPublicKeyPem?: string;
  /** Peer's instance name. */
  peerInstanceName?: string;
  /** When this handshake started (for timeout). */
  startedAt: number;
};

// ─── HandshakeManager ───────────────────────────────────────

export type HandshakeManagerOptions = {
  identity: FederationLocalIdentity;
  trustStore: TrustStore;
  handler: MessageHandler;
  /** Handshake timeout in ms (default 15 000). */
  timeoutMs?: number;
};

/**
 * Manages the 3-step mutual authentication handshake for a single
 * connection.
 *
 * Flow:
 * 1. Initiator → HELLO { peerId, publicKey, challenge, instanceName }
 * 2. Responder → HELLO_ACK { peerId, publicKey, challengeResponse, challenge }
 * 3. Initiator → AUTH_COMPLETE { challengeResponse }
 * 4. Both sides mark the connection as authenticated.
 *
 * @example
 * ```ts
 * // Initiator side
 * const hs = new HandshakeManager({ identity, trustStore, handler });
 * const hello = hs.createHello();
 * send(JSON.stringify(hello));
 *
 * // On receiving HELLO_ACK:
 * const result = hs.handleHelloAck(msg);
 * if (result.ok) send(JSON.stringify(result.response));
 *
 * // Responder side
 * const hs = new HandshakeManager({ identity, trustStore, handler });
 * const result = hs.handleHello(msg);
 * if (result.ok) send(JSON.stringify(result.response));
 *
 * // On receiving AUTH_COMPLETE:
 * const result = hs.handleAuthComplete(msg);
 * if (result.ok) // authenticated!
 * ```
 */
export class HandshakeManager {
  private readonly identity: FederationLocalIdentity;
  private readonly trustStore: TrustStore;
  private readonly handler: MessageHandler;
  readonly timeoutMs: number;

  /** Current handshake state (one per connection). */
  private state: PendingHandshakeState | null = null;

  constructor(opts: HandshakeManagerOptions) {
    this.identity = opts.identity;
    this.trustStore = opts.trustStore;
    this.handler = opts.handler;
    this.timeoutMs = opts.timeoutMs ?? 15_000;
  }

  /** Current handshake phase. */
  get phase(): HandshakePhase {
    return this.state?.phase ?? "idle";
  }

  /** Peer ID (available after receiving HELLO or HELLO_ACK). */
  get peerId(): string | undefined {
    return this.state?.peerId;
  }

  // ─── Initiator: Step 1 ────────────────────────────────

  /**
   * Create a HELLO message to initiate a handshake.
   */
  createHello(): FederationMessage {
    const challenge = generateChallenge();

    this.state = {
      phase: "hello_sent",
      ourChallenge: challenge,
      startedAt: Date.now(),
    };

    const payload: HelloPayload = {
      peerId: this.identity.peerId,
      publicKey: this.identity.publicKeyPem,
      challenge,
      instanceName: this.identity.name,
    };

    return this.handler.createMessage(FederationMessageType.HELLO, payload);
  }

  // ─── Responder: Step 2 ────────────────────────────────

  /**
   * Handle an incoming HELLO message and produce a HELLO_ACK response.
   *
   * Validates that the sender is in our trust store before responding.
   */
  handleHello(
    msg: FederationMessage,
  ): { ok: true; response: FederationMessage } | { ok: false; error: string } {
    if (msg.type !== FederationMessageType.HELLO) {
      return { ok: false, error: `Expected HELLO, got ${msg.type}` };
    }

    const payload = msg.payload as HelloPayload;
    if (!payload || typeof payload.peerId !== "string" || typeof payload.challenge !== "string") {
      return { ok: false, error: "Invalid HELLO payload" };
    }

    // Verify the sender is in our trust store.
    const peer = this.trustStore.getPeer(payload.peerId);
    if (!peer) {
      return { ok: false, error: `Peer not in trust store: ${payload.peerId}` };
    }

    // Sign their challenge to prove we hold our private key.
    const challengeResponse = signPayload(this.identity.privateKeyPem, payload.challenge);

    // Generate our own counter-challenge.
    const ourChallenge = generateChallenge();

    this.state = {
      phase: "hello_ack_sent",
      ourChallenge,
      peerChallenge: payload.challenge,
      peerId: payload.peerId,
      peerPublicKeyPem: payload.publicKey,
      peerInstanceName: payload.instanceName,
      startedAt: Date.now(),
    };

    const ackPayload: HelloAckPayload = {
      peerId: this.identity.peerId,
      publicKey: this.identity.publicKeyPem,
      challengeResponse,
      challenge: ourChallenge,
    };

    const response = this.handler.createMessage(
      FederationMessageType.HELLO_ACK,
      ackPayload,
      payload.peerId,
    );

    return { ok: true, response };
  }

  // ─── Initiator: Step 3 ────────────────────────────────

  /**
   * Handle an incoming HELLO_ACK and produce an AUTH_COMPLETE response.
   *
   * Verifies the peer's challenge response, then signs their counter-challenge.
   */
  handleHelloAck(
    msg: FederationMessage,
  ): { ok: true; response: FederationMessage; peerId: string } | { ok: false; error: string } {
    if (!this.state || this.state.phase !== "hello_sent") {
      return { ok: false, error: "No pending outgoing handshake" };
    }

    if (msg.type !== FederationMessageType.HELLO_ACK) {
      return { ok: false, error: `Expected HELLO_ACK, got ${msg.type}` };
    }

    const payload = msg.payload as HelloAckPayload;
    if (
      !payload ||
      typeof payload.peerId !== "string" ||
      typeof payload.challengeResponse !== "string" ||
      typeof payload.challenge !== "string"
    ) {
      return { ok: false, error: "Invalid HELLO_ACK payload" };
    }

    // Look up the peer.
    const peer = this.trustStore.getPeer(payload.peerId);
    if (!peer) {
      return { ok: false, error: `Peer not in trust store: ${payload.peerId}` };
    }

    // Verify their challenge response.
    const valid = verifySignature(
      peer.identity.publicKeyPem,
      this.state.ourChallenge,
      payload.challengeResponse,
    );
    if (!valid) {
      return { ok: false, error: "Challenge response verification failed" };
    }

    // Sign their counter-challenge.
    const counterResponse = signPayload(this.identity.privateKeyPem, payload.challenge);

    const authPayload: AuthCompletePayload = {
      challengeResponse: counterResponse,
    };

    const response = this.handler.createMessage(
      FederationMessageType.AUTH_COMPLETE,
      authPayload,
      payload.peerId,
    );

    // Mark authenticated.
    this.state = {
      ...this.state,
      phase: "authenticated",
      peerId: payload.peerId,
      peerPublicKeyPem: payload.publicKey,
    };

    return { ok: true, response, peerId: payload.peerId };
  }

  // ─── Responder: Step 4 ────────────────────────────────

  /**
   * Handle an incoming AUTH_COMPLETE message to finalize the handshake.
   *
   * Verifies the initiator's counter-challenge response.
   */
  handleAuthComplete(
    msg: FederationMessage,
  ): { ok: true; peerId: string } | { ok: false; error: string } {
    if (!this.state || this.state.phase !== "hello_ack_sent") {
      return { ok: false, error: "No pending inbound handshake" };
    }

    if (msg.type !== FederationMessageType.AUTH_COMPLETE) {
      return { ok: false, error: `Expected AUTH_COMPLETE, got ${msg.type}` };
    }

    const payload = msg.payload as AuthCompletePayload;
    if (!payload || typeof payload.challengeResponse !== "string") {
      return { ok: false, error: "Invalid AUTH_COMPLETE payload" };
    }

    // Look up the peer to verify signature.
    const peerId = this.state.peerId!;
    const peer = this.trustStore.getPeer(peerId);
    if (!peer) {
      return { ok: false, error: `Peer not in trust store: ${peerId}` };
    }

    // Verify counter-challenge response.
    const valid = verifySignature(
      peer.identity.publicKeyPem,
      this.state.ourChallenge,
      payload.challengeResponse,
    );
    if (!valid) {
      return { ok: false, error: "Counter-challenge response verification failed" };
    }

    // Mark authenticated.
    this.state = {
      ...this.state,
      phase: "authenticated",
    };

    return { ok: true, peerId };
  }

  /**
   * Check if the handshake has timed out.
   */
  isTimedOut(): boolean {
    if (!this.state || this.state.phase === "idle" || this.state.phase === "authenticated") {
      return false;
    }
    return Date.now() - this.state.startedAt > this.timeoutMs;
  }

  /**
   * Reset the handshake state.
   */
  reset(): void {
    this.state = null;
  }
}
