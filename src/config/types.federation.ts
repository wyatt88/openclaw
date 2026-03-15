/**
 * Federation configuration types for the OpenClaw config layer.
 *
 * Follows the same style as other `types.*.ts` files in this directory
 * (e.g. types.gateway.ts, types.acp.ts).
 *
 * The Zod schema lives in `src/federation/config.ts` — these types
 * are the "plain TypeScript" view used by the rest of the codebase.
 */

import type { FederationCapability } from "../federation/types.js";

// ─── Rate Limit ─────────────────────────────────────────────

/**
 * Rate limit configuration for federation messages.
 * Mirrors {@link CapabilityGrant.rateLimit} but as a standalone config type.
 */
export type FederationRateLimitConfig = {
  /** Max inbound messages per minute from a single peer. */
  maxMessagesPerMinute?: number;
  /** Max inbound messages per hour from a single peer. */
  maxMessagesPerHour?: number;
  /** Max inbound messages per day from a single peer. */
  maxMessagesPerDay?: number;
};

// ─── Peer Endpoint (config representation) ──────────────────

/**
 * Network endpoint for reaching a federated peer.
 * Config-layer mirror of {@link PeerEndpoint}.
 */
export type FederationPeerEndpointConfig = {
  /** WebSocket URL for real-time communication (wss://). */
  wsUrl?: string;
  /** HTTPS fallback URL for HTTP API calls. */
  httpUrl?: string;
  /** TLS certificate SHA-256 fingerprint for pinning. */
  tlsFingerprint?: string;
  /** Tailscale MagicDNS hostname (auto-discovered). */
  tailnetHostname?: string;
};

// ─── Trusted Peer (config representation) ───────────────────

/**
 * A pre-approved peer declared in config.yaml.
 *
 * At runtime the federation subsystem enriches this with a derived
 * `peerId` (SHA-256 of publicKey) and handshake state.
 */
export type FederationTrustedPeerConfig = {
  /** Ed25519 public key (PEM or raw base64). */
  publicKey: string;
  /** Human-readable display name. */
  name: string;
  /** Network endpoint(s). */
  endpoint: FederationPeerEndpointConfig;
  /** Capabilities to grant this peer on first handshake. */
  capabilities?: FederationCapability[];
  /** Per-peer rate limits (overrides federation.defaultRateLimit). */
  rateLimit?: FederationRateLimitConfig;
};

// ─── Simplified Peer (token auth) ───────────────────────────

/**
 * Simplified peer configuration using token auth.
 * No Ed25519 key exchange needed — uses gateway token for auth.
 * Suitable for trusted internal networks or quick setup.
 */
export type FederationSimplePeerConfig = {
  /** Human-readable display name for the peer. */
  name: string;
  /** Peer's public endpoint URL (wss:// or https://). */
  endpoint: string;
  /** Peer's gateway auth token for API access. */
  token: string;
  /** Capabilities to grant this peer. Defaults to ["chat"]. */
  capabilities?: FederationCapability[];
};

// ─── Top-level Federation Config ────────────────────────────

/**
 * Configuration for the `federation:` section of config.yaml.
 *
 * This type matches the Zod schema in `src/federation/config.ts`
 * and the runtime type in `src/federation/types.ts`.
 */
export type FederationConfigSection = {
  /** Enable the federation subsystem (default: false). */
  enabled?: boolean;
  /** Display name for this instance in federation handshakes. */
  instanceName?: string;
  /** Pre-approved trusted peers. */
  trustedPeers?: FederationTrustedPeerConfig[];
  /** Default rate limits for peers without per-peer overrides. */
  defaultRateLimit?: FederationRateLimitConfig;
  /** Allow peers to introduce other peers (Web of Trust). */
  allowIntroductions?: boolean;
  /** Maximum trust chain depth for introductions (1–10, default: 2). */
  maxTrustDepth?: number;
  /** Path to the persistent trust store file. */
  trustStorePath?: string;
  /** Path to the Ed25519 identity keypair file. */
  identityKeyPath?: string;
  /** This instance's public endpoint URL for federation. */
  endpoint?: string;
  /** Simplified peer list using token auth (alternative to trustedPeers). */
  peers?: FederationSimplePeerConfig[];
  /** Dedicated federation WebSocket listener port. */
  port?: number;
  /** Bind address for the federation listener. */
  bind?: "auto" | "lan" | "loopback" | "tailnet";
};

// ─── Federation Bind Mode ───────────────────────────────────

export type FederationBindMode = "auto" | "lan" | "loopback" | "tailnet";
