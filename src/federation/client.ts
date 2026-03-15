/**
 * Federation Client — P2P bidirectional communication
 *
 * Each OpenClaw instance is both client AND server:
 * - Listens for incoming peer connections (via Gateway WS)
 * - Initiates outgoing connections to known peers
 * - All messages are signed with Ed25519
 * - Challenge-Response mutual authentication
 */

import {
  createSignedMessage,
  verifySignedMessage,
  generateChallenge,
  signPayload,
  verifySignature,
  createCapabilityGrant,
  loadOrCreateFederationIdentity,
  formatPeerId,
} from "./crypto.js";
import { SimplePeerConnectionPool } from "./transport.js";
import { TrustStore } from "./trust-store.js";
import type {
  FederationConfig,
  FederationLocalIdentity,
  FederationStatus,
  HelloMessage,
  HelloAckMessage,
  HelloVerifiedMessage,
  ChatMessage,
  ChatResponseMessage,
  SignedMessage,
  SimplePeerConfig,
  FederationCapability,
} from "./types.js";

// ─── Federation Node ────────────────────────────────────────

type PendingHandshake = {
  challenge: string;
  counterChallenge?: string;
  startedAt: number;
  peerId?: string;
};

type ChatHandler = (params: {
  peerId: string;
  peerName: string;
  conversationId: string;
  text: string;
}) => Promise<string>;

type EventHandler = (event: string, data: unknown) => void;

/**
 * Unified peer info returned by {@link FederationNode.getAllPeers}.
 * Works for both Ed25519 (trust store) and token-auth (simplified) peers.
 */
export type PeerInfo = {
  /** Human-readable peer name. */
  name: string;
  /** Peer ID — SHA-256 hash for Ed25519 peers, `token:<name>` for simplified peers. */
  peerId: string;
  /** Authentication type. */
  type: "ed25519" | "token";
  /** Whether the peer is currently connected. */
  connected: boolean;
  /** Trust level. Simplified peers are always "direct". */
  trust: "direct" | "vouched" | "unknown";
  /** Capabilities granted to/from this peer. */
  capabilities: FederationCapability[];
  /** Last communication timestamp, if known. */
  lastSeenAt?: number;
  /** Primary endpoint URL, if known. */
  endpoint?: string;
};

/**
 * FederationNode — manages all peer connections and communication.
 *
 * This is the main entry point for federation functionality.
 * It handles identity, trust, handshakes, and message routing.
 */
export class FederationNode {
  readonly identity: FederationLocalIdentity;
  readonly trustStore: TrustStore;
  private chatHandler: ChatHandler | null = null;
  private eventHandler: EventHandler | null = null;
  private readonly pendingHandshakes = new Map<string, PendingHandshake>();
  private readonly conversations = new Map<
    string,
    { peerId: string; messages: Array<{ role: string; text: string }> }
  >();
  private readonly config: FederationConfig;

  /**
   * Simplified peers (token-based auth) keyed by a synthetic peerId (`token:<name>`).
   * These peers do not use Ed25519 handshakes.
   */
  readonly simplePeers = new Map<string, SimplePeerConfig>();

  /**
   * Map from peer name (lowercase) → synthetic peerId for simple peers.
   */
  private readonly simplePeerNameIndex = new Map<string, string>();

  /**
   * Connection pool for simplified (token-auth) peers.
   * Manages WebSocket connections, heartbeat, and auto-reconnect.
   */
  readonly simplePeerPool = new SimplePeerConnectionPool();

  constructor(config: FederationConfig) {
    this.config = config;
    this.identity = loadOrCreateFederationIdentity(config.instanceName);
    this.trustStore = new TrustStore();

    // Import pre-configured trusted peers
    if (config.trustedPeers) {
      for (const peerConfig of config.trustedPeers) {
        const peerId = peerConfig.publicKey.includes("BEGIN")
          ? undefined // Will be derived
          : peerConfig.publicKey;

        const grant = createCapabilityGrant(this.identity, {
          grantee: peerId ?? "pending",
          capabilities: peerConfig.capabilities ?? ["chat"],
          rateLimit: peerConfig.rateLimit ?? config.defaultRateLimit,
        });

        // Only add if not already in trust store
        const existingPeers = this.trustStore.listPeers();
        const alreadyExists = existingPeers.some(
          (p) =>
            p.identity.publicKeyPem === peerConfig.publicKey || p.identity.name === peerConfig.name,
        );

        if (!alreadyExists) {
          try {
            this.trustStore.addDirectPeer({
              identity: {
                peerId: peerId ?? "",
                publicKeyPem: peerConfig.publicKey,
                name: peerConfig.name,
              },
              endpoint: peerConfig.endpoint,
              grant,
            });
          } catch {
            // Skip invalid peer configs
          }
        }
      }
    }

    // Import simplified peers (token-based auth)
    if (config.peers) {
      for (const peer of config.peers) {
        const syntheticId = `token:${peer.name}`;
        this.simplePeers.set(syntheticId, peer);
        this.simplePeerNameIndex.set(peer.name.toLowerCase(), syntheticId);
      }
    }
  }

  /**
   * Register a handler for incoming chat messages.
   * The handler receives the message and returns a response.
   */
  onChat(handler: ChatHandler): void {
    this.chatHandler = handler;
  }

  /**
   * Register a handler for federation events.
   */
  onEvent(handler: EventHandler): void {
    this.eventHandler = handler;
  }

  private emit(event: string, data: unknown): void {
    this.eventHandler?.(event, data);
  }

  // ─── Handshake (Challenge-Response) ─────────────────────

  /**
   * Step 1: Initiate handshake with a peer.
   * Returns a signed Hello message.
   */
  createHello(): SignedMessage {
    const challenge = generateChallenge();
    const hello: HelloMessage = {
      type: "hello",
      data: {
        identity: {
          peerId: this.identity.peerId,
          publicKeyPem: this.identity.publicKeyPem,
          name: this.identity.name,
        },
        challenge,
        protocolVersion: 1,
        timestamp: Date.now(),
      },
    };

    this.pendingHandshakes.set("outgoing", {
      challenge,
      startedAt: Date.now(),
    });

    return createSignedMessage(this.identity, hello);
  }

  /**
   * Step 2: Handle incoming Hello, create HelloAck.
   * Verifies the sender and responds with counter-challenge.
   */
  handleHello(
    message: SignedMessage,
  ): { ok: true; response: SignedMessage } | { ok: false; error: string } {
    // Look up sender in trust store
    const peer = this.trustStore.getPeer(message.senderId);
    if (!peer) {
      return { ok: false, error: `Unknown peer: ${formatPeerId(message.senderId)}` };
    }

    // Verify message signature
    const verified = verifySignedMessage(peer.identity.publicKeyPem, message);
    if (!verified.valid) {
      return { ok: false, error: `Invalid signature: ${verified.error}` };
    }

    const hello = verified.payload as HelloMessage;
    if (hello.type !== "hello") {
      return { ok: false, error: `Expected hello, got ${String(hello.type)}` };
    }

    // Sign their challenge (proves we have our private key)
    const challengeResponse = signPayload(this.identity.privateKeyPem, hello.data.challenge);

    // Create our counter-challenge
    const counterChallenge = generateChallenge();

    this.pendingHandshakes.set(message.senderId, {
      challenge: hello.data.challenge,
      counterChallenge,
      startedAt: Date.now(),
      peerId: message.senderId,
    });

    const ack: HelloAckMessage = {
      type: "hello.ack",
      data: {
        identity: {
          peerId: this.identity.peerId,
          publicKeyPem: this.identity.publicKeyPem,
          name: this.identity.name,
        },
        challengeResponse,
        counterChallenge,
        protocolVersion: 1,
        timestamp: Date.now(),
      },
    };

    return { ok: true, response: createSignedMessage(this.identity, ack) };
  }

  /**
   * Step 3: Handle HelloAck, create HelloVerified.
   * Verifies the peer's challenge response and sends final verification.
   */
  handleHelloAck(
    message: SignedMessage,
  ): { ok: true; response: SignedMessage; peerId: string } | { ok: false; error: string } {
    const pending = this.pendingHandshakes.get("outgoing");
    if (!pending) {
      return { ok: false, error: "No pending outgoing handshake" };
    }

    // Look up sender
    const peer = this.trustStore.getPeer(message.senderId);
    if (!peer) {
      return { ok: false, error: `Unknown peer: ${formatPeerId(message.senderId)}` };
    }

    // Verify message
    const verified = verifySignedMessage(peer.identity.publicKeyPem, message);
    if (!verified.valid) {
      return { ok: false, error: `Invalid signature: ${verified.error}` };
    }

    const ack = verified.payload as HelloAckMessage;
    if (ack.type !== "hello.ack") {
      return { ok: false, error: `Expected hello.ack, got ${String(ack.type)}` };
    }

    // Verify their challenge response (proves they have their private key)
    const challengeValid = verifySignature(
      peer.identity.publicKeyPem,
      pending.challenge,
      ack.data.challengeResponse,
    );
    if (!challengeValid) {
      return { ok: false, error: "Challenge response verification failed" };
    }

    // Sign their counter-challenge
    const counterChallengeResponse = signPayload(
      this.identity.privateKeyPem,
      ack.data.counterChallenge,
    );

    // Create capability grant for this peer
    const grant = createCapabilityGrant(this.identity, {
      grantee: message.senderId,
      capabilities: peer.grantedCapabilities.capabilities,
      rateLimit: peer.grantedCapabilities.rateLimit,
    });

    const verifiedMsg: HelloVerifiedMessage = {
      type: "hello.verified",
      data: {
        counterChallengeResponse,
        capabilityGrant: grant,
        timestamp: Date.now(),
      },
    };

    this.pendingHandshakes.delete("outgoing");
    this.trustStore.setConnected(message.senderId, true);
    this.emit("peer.connected", { peerId: message.senderId, peerName: peer.identity.name });

    return {
      ok: true,
      response: createSignedMessage(this.identity, verifiedMsg),
      peerId: message.senderId,
    };
  }

  /**
   * Step 4: Handle HelloVerified (completes handshake on responder side).
   */
  handleHelloVerified(message: SignedMessage): { ok: true } | { ok: false; error: string } {
    const pending = this.pendingHandshakes.get(message.senderId);
    if (!pending?.counterChallenge) {
      return { ok: false, error: "No pending handshake for this peer" };
    }

    const peer = this.trustStore.getPeer(message.senderId);
    if (!peer) {
      return { ok: false, error: `Unknown peer: ${formatPeerId(message.senderId)}` };
    }

    const verified = verifySignedMessage(peer.identity.publicKeyPem, message);
    if (!verified.valid) {
      return { ok: false, error: `Invalid signature: ${verified.error}` };
    }

    const verifiedMsg = verified.payload as HelloVerifiedMessage;

    // Verify counter-challenge response
    const valid = verifySignature(
      peer.identity.publicKeyPem,
      pending.counterChallenge,
      verifiedMsg.data.counterChallengeResponse,
    );
    if (!valid) {
      return { ok: false, error: "Counter-challenge verification failed" };
    }

    // Store received capability grant
    if (verifiedMsg.data.capabilityGrant) {
      this.trustStore.setReceivedCapabilities(message.senderId, verifiedMsg.data.capabilityGrant);
    }

    this.pendingHandshakes.delete(message.senderId);
    this.trustStore.setConnected(message.senderId, true);
    this.emit("peer.connected", { peerId: message.senderId, peerName: peer.identity.name });

    return { ok: true };
  }

  // ─── Chat ───────────────────────────────────────────────

  /**
   * Send a chat message to a connected peer.
   */
  createChatMessage(params: {
    peerId: string;
    text: string;
    conversationId?: string;
  }): { ok: true; message: SignedMessage; conversationId: string } | { ok: false; error: string } {
    const peer = this.trustStore.getPeer(params.peerId);
    if (!peer) {
      return { ok: false, error: `Unknown peer: ${params.peerId}` };
    }
    if (!peer.connected) {
      return { ok: false, error: `Peer not connected: ${peer.identity.name}` };
    }

    // Check capability
    if (!this.trustStore.weHaveCapabilityOn(params.peerId, "chat")) {
      return { ok: false, error: `No chat capability granted by peer ${peer.identity.name}` };
    }

    // Check rate limit (on our side)
    if (!this.trustStore.checkRateLimit(params.peerId)) {
      return { ok: false, error: "Rate limit exceeded" };
    }

    const conversationId =
      params.conversationId ?? `conv-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    const chat: ChatMessage = {
      type: "chat",
      data: {
        conversationId,
        text: params.text,
      },
    };

    return {
      ok: true,
      message: createSignedMessage(this.identity, chat),
      conversationId,
    };
  }

  /**
   * Handle an incoming chat message from a peer.
   */
  async handleChatMessage(
    message: SignedMessage,
  ): Promise<{ ok: true; response: SignedMessage } | { ok: false; error: string }> {
    const peer = this.trustStore.getPeer(message.senderId);
    if (!peer) {
      return { ok: false, error: `Unknown peer: ${message.senderId}` };
    }

    // Verify
    const verified = verifySignedMessage(peer.identity.publicKeyPem, message);
    if (!verified.valid) {
      return { ok: false, error: `Invalid signature: ${verified.error}` };
    }

    // Check capability
    if (!this.trustStore.peerHasCapability(message.senderId, "chat")) {
      return { ok: false, error: "Peer does not have chat capability" };
    }

    // Check rate limit
    if (!this.trustStore.checkRateLimit(message.senderId)) {
      return { ok: false, error: "Rate limit exceeded" };
    }

    const chat = verified.payload as ChatMessage;
    if (chat.type !== "chat") {
      return { ok: false, error: `Expected chat, got ${String(chat.type)}` };
    }

    // Delegate to chat handler (runs the Agent in a federation session)
    if (!this.chatHandler) {
      return { ok: false, error: "No chat handler registered" };
    }

    const responseText = await this.chatHandler({
      peerId: message.senderId,
      peerName: peer.identity.name,
      conversationId: chat.data.conversationId,
      text: chat.data.text,
    });

    const response: ChatResponseMessage = {
      type: "chat.response",
      data: {
        conversationId: chat.data.conversationId,
        text: responseText,
        deferredToOwner: false,
      },
    };

    return { ok: true, response: createSignedMessage(this.identity, response) };
  }

  // ─── Simple Peer Resolution ──────────────────────────────

  /**
   * Resolve a simple peer by name (case-insensitive).
   * Returns the SimplePeerConfig and its synthetic peerId, or undefined.
   */
  resolveSimplePeer(nameOrId: string): { peerId: string; peer: SimplePeerConfig } | undefined {
    // Direct ID lookup
    if (this.simplePeers.has(nameOrId)) {
      return { peerId: nameOrId, peer: this.simplePeers.get(nameOrId)! };
    }
    // Name lookup (case-insensitive)
    const syntheticId = this.simplePeerNameIndex.get(nameOrId.toLowerCase());
    if (syntheticId) {
      return { peerId: syntheticId, peer: this.simplePeers.get(syntheticId)! };
    }
    return undefined;
  }

  /**
   * List all simple (token-auth) peers.
   */
  listSimplePeers(): Array<{ peerId: string; peer: SimplePeerConfig }> {
    return Array.from(this.simplePeers.entries()).map(([peerId, peer]) => ({ peerId, peer }));
  }

  // ─── Status ─────────────────────────────────────────────

  getStatus(): FederationStatus {
    const peers = this.trustStore.listPeers().map((peer) => ({
      peerId: peer.identity.peerId,
      peerName: peer.identity.name,
      connected: peer.connected,
      trust: peer.trust,
      lastSeenAt: peer.lastSeenAt,
      capabilities: peer.grantedCapabilities.capabilities,
      endpoint: peer.endpoint.wsUrl ?? peer.endpoint.httpUrl,
    }));

    // Include simple peers in status
    for (const [syntheticId, simplePeer] of this.simplePeers) {
      peers.push({
        peerId: syntheticId,
        peerName: simplePeer.name,
        connected: false, // Connection state managed by transport
        trust: "direct" as const,
        lastSeenAt: undefined,
        capabilities: simplePeer.capabilities ?? ["chat"],
        endpoint: simplePeer.endpoint,
        tokenAuth: true,
      });
    }

    return {
      enabled: this.config.enabled,
      identity: {
        peerId: this.identity.peerId,
        publicKeyPem: this.identity.publicKeyPem,
        name: this.identity.name,
      },
      peers,
      totalConnected: peers.filter((p) => p.connected).length,
      totalTrusted: peers.filter((p) => p.trust === "direct" || p.trust === "vouched").length,
    };
  }

  /**
   * Disconnect a peer.
   */
  disconnectPeer(peerId: string): void {
    this.trustStore.setConnected(peerId, false);
    this.pendingHandshakes.delete(peerId);
    this.emit("peer.disconnected", { peerId });
  }

  // ─── Simplified Peer Management ─────────────────────────

  /**
   * Connect to simplified peers from config.
   *
   * Each peer is registered in the local `simplePeers` map and a
   * WebSocket connection is established via the {@link SimplePeerConnectionPool}.
   * Failed connections will automatically retry with exponential backoff.
   *
   * @param peers - Array of simplified peer configurations.
   */
  async connectSimplePeers(peers: SimplePeerConfig[]): Promise<void> {
    for (const peer of peers) {
      const syntheticId = `token:${peer.name}`;

      // Register in local maps.
      this.simplePeers.set(syntheticId, peer);
      this.simplePeerNameIndex.set(peer.name.toLowerCase(), syntheticId);

      // Add to the connection pool (handles connect + auto-reconnect).
      await this.simplePeerPool.add({
        peerName: peer.name,
        endpoint: peer.endpoint,
        token: peer.token,
      });
    }
  }

  /**
   * Get information about all connected peers — both Ed25519 (trust store)
   * and token-auth (simplified) peers.
   *
   * @returns Array of peer info objects with name, type, and connection status.
   */
  getAllPeers(): PeerInfo[] {
    const result: PeerInfo[] = [];

    // Ed25519 peers from the trust store.
    for (const peer of this.trustStore.listPeers()) {
      result.push({
        name: peer.identity.name,
        peerId: peer.identity.peerId,
        type: "ed25519",
        connected: peer.connected,
        trust: peer.trust,
        capabilities: peer.grantedCapabilities.capabilities,
        lastSeenAt: peer.lastSeenAt,
        endpoint: peer.endpoint.wsUrl ?? peer.endpoint.httpUrl ?? undefined,
      });
    }

    // Simplified (token-auth) peers from the connection pool.
    for (const [syntheticId, config] of this.simplePeers) {
      const conn = this.simplePeerPool.get(config.name);
      result.push({
        name: config.name,
        peerId: syntheticId,
        type: "token",
        connected: conn?.status === "connected",
        trust: "direct",
        capabilities: config.capabilities ?? ["chat"],
        lastSeenAt: undefined,
        endpoint: config.endpoint,
      });
    }

    return result;
  }

  /**
   * Send a chat message to a simplified (token-auth) peer by name.
   *
   * The message is sent as a JSON object over the WebSocket connection.
   * Returns a promise that resolves with the peer's text response,
   * or rejects if the peer is not connected or the request times out.
   *
   * @param name - The peer's display name (case-insensitive).
   * @param message - The chat message text to send.
   * @param timeoutMs - Response timeout in milliseconds (default: 60000).
   * @returns The peer's text response.
   * @throws {Error} If the peer is not found, not connected, or the request times out.
   */
  async chatWithSimplePeer(name: string, message: string, timeoutMs = 60_000): Promise<string> {
    const syntheticId = this.simplePeerNameIndex.get(name.toLowerCase());
    if (!syntheticId) {
      throw new Error(`Simple peer "${name}" not found`);
    }

    const peerConfig = this.simplePeers.get(syntheticId);
    if (!peerConfig) {
      throw new Error(`Simple peer config for "${name}" not found`);
    }

    const conn = this.simplePeerPool.get(peerConfig.name);
    if (!conn || conn.status !== "connected") {
      throw new Error(
        `Simple peer "${name}" is not connected (status: ${conn?.status ?? "unknown"})`,
      );
    }

    // Check capability.
    const capabilities = peerConfig.capabilities ?? ["chat"];
    if (!capabilities.includes("chat")) {
      throw new Error(`Simple peer "${name}" does not have the "chat" capability`);
    }

    const conversationId = `conv-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    // Send the chat message.
    await conn.send({
      type: "chat",
      data: {
        conversationId,
        text: message,
        senderName: this.identity.name,
      },
    });

    // Wait for a response with matching conversationId.
    return new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        conn.removeListener("message", handler);
        reject(new Error(`Chat response from "${name}" timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const handler = (data: unknown) => {
        if (typeof data !== "object" || data === null) {
          return;
        }

        const msg = data as Record<string, unknown>;
        if (msg.type !== "chat.response") {
          return;
        }

        const responseData = msg.data as Record<string, unknown> | undefined;
        if (!responseData || responseData.conversationId !== conversationId) {
          return;
        }

        clearTimeout(timer);
        conn.removeListener("message", handler);
        resolve(
          typeof responseData.text === "string"
            ? responseData.text
            : JSON.stringify(responseData.text ?? ""),
        );
      };

      conn.on("message", handler);
    });
  }
}
