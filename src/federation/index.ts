/**
 * Federation Module — Decentralized Multi-Instance OpenClaw Communication
 *
 * Inspired by blockchain P2P patterns:
 * - Ed25519 keypair identity (no shared secrets)
 * - Challenge-Response mutual authentication
 * - Signed Capability Grants (fine-grained permissions)
 * - Web of Trust (direct / vouched / unknown)
 * - Message signing (non-repudiation + tamper-proof)
 * - Federation Sessions (isolated, tool-restricted)
 *
 * Architecture:
 *   Each OpenClaw instance = a "node" in a P2P network.
 *   Nodes communicate via signed messages over WSS.
 *   Trust is established through public key exchange + challenge-response.
 *   No central server. No shared secrets. No tokens.
 *
 * @see docs/research/multi-instance-communication.md
 */

// Core
export { FederationNode } from "./client.js";
export { FederationTransport } from "./transport.js";
export { TrustStore } from "./trust-store.js";

// Gateway Integration
export { initFederation, getDefaultFederationConfig } from "./gateway-integration.js";
export type { FederationHandle, FederationInitOptions } from "./gateway-integration.js";

// Crypto
export {
  loadOrCreateFederationIdentity,
  createSignedMessage,
  verifySignedMessage,
  createCapabilityGrant,
  verifyCapabilityGrant,
  generateChallenge,
  signPayload,
  verifySignature,
  formatPeerId,
  derivePeerIdFromPublicKey,
} from "./crypto.js";

// Pairing
export { PairingManager, encodePairingCode, decodePairingCode } from "./pairing.js";
export type { PairingCodeData, PairingResult } from "./pairing.js";

// Tools
export { createFederationTools } from "./tools.js";

// Web UI HTTP API
export { registerFederationWebRoutes } from "./web-ui.js";
export type { FederationWebRouteOptions } from "./web-ui.js";

// Types
export type {
  FederationConfig,
  FederationIdentity,
  FederationLocalIdentity,
  FederationCapability,
  FederationStatus,
  FederationPeerHealth,
  TrustLevel,
  TrustedPeer,
  PeerEndpoint,
  CapabilityGrant,
  SignedMessage,
  FederationMessagePayload,
  FederationMessageType,
  SimplePeerConfig,
  DelegateMessage,
  DelegateResponseMessage,
  BroadcastMessage,
} from "./types.js";

export {
  FEDERATION_PROTOCOL_VERSION,
  FEDERATION_SYSTEM_PROMPT,
  FEDERATION_TOOL_ALLOWLIST,
} from "./types.js";
