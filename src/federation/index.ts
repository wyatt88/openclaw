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
export { TrustStore } from "./trust-store.js";

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

// Tools
export { createFederationTools } from "./tools.js";

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
} from "./types.js";

export {
  FEDERATION_PROTOCOL_VERSION,
  FEDERATION_SYSTEM_PROMPT,
  FEDERATION_TOOL_ALLOWLIST,
} from "./types.js";
