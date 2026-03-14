/**
 * Federation Module — Multi-Instance OpenClaw Communication
 *
 * Phase 1: OpenAI API Bridge
 *   - FederationRegistry: peer management
 *   - sendChatToPeer(): HTTP client for /v1/chat/completions
 *   - federation_chat tool: Agent-accessible cross-instance messaging
 *
 * Phase 2 (planned): WS Federation Client
 *   - Long-lived WebSocket connections between Gateways
 *   - Cross-instance sessions_send
 *
 * Phase 3 (planned): Event Bridge
 *   - Cross-instance event subscription
 *   - Shared context synchronization
 *
 * @see docs/research/multi-instance-communication.md
 */

export { FederationRegistry, sendChatToPeer, checkPeerHealth } from "./client.js";
export { createFederationTools } from "./tools.js";
export type {
  FederationConfig,
  FederationPeer,
  FederationChatResult,
  FederationPeerHealth,
  FederationCapability,
} from "./types.js";
