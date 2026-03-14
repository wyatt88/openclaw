/**
 * Federation Types — Multi-Instance OpenClaw Communication
 *
 * Phase 1: OpenAI API Bridge
 * Enables one OpenClaw instance to communicate with another via standard
 * OpenAI-compatible HTTP API (/v1/chat/completions).
 *
 * @see docs/research/multi-instance-communication.md
 */

/**
 * A known peer Gateway instance that this Gateway can communicate with.
 */
export type FederationPeer = {
  /** Unique identifier for this peer (e.g., "ark-secondary") */
  id: string;
  /** Display name shown in logs and UI */
  name: string;
  /** Base URL of the peer's Gateway HTTP API (e.g., "https://peer.tailnet:18789") */
  url: string;
  /** Auth token for the peer's Gateway */
  token?: string;
  /** Password auth (alternative to token) */
  password?: string;
  /** TLS fingerprint for certificate pinning */
  tlsFingerprint?: string;
  /** Enabled capabilities for this peer */
  capabilities?: FederationCapability[];
  /** Maximum timeout for requests to this peer (ms) */
  timeoutMs?: number;
};

export type FederationCapability =
  | "chat"        // Can send chat messages via /v1/chat/completions
  | "sessions"    // Can list/send to sessions (Phase 2)
  | "events"      // Can subscribe to events (Phase 3)
  | "tools";      // Can invoke remote tools (Phase 3)

/**
 * Configuration for the federation subsystem.
 */
export type FederationConfig = {
  /** Enable federation */
  enabled: boolean;
  /** This instance's unique ID */
  instanceId: string;
  /** Known peer Gateways */
  peers: FederationPeer[];
};

/**
 * Result of a federation chat request.
 */
export type FederationChatResult = {
  ok: boolean;
  peerId: string;
  /** The assistant's response text */
  text?: string;
  /** Model used by the peer */
  model?: string;
  /** Usage from the peer */
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  };
  /** Error message if failed */
  error?: string;
  /** Response time in ms */
  latencyMs: number;
};

/**
 * Result of a federation peer health check.
 */
export type FederationPeerHealth = {
  peerId: string;
  peerName: string;
  reachable: boolean;
  latencyMs: number;
  error?: string;
  checkedAt: number;
};
