/**
 * Federation Gateway Integration
 *
 * Connects the Federation module into the Gateway startup flow:
 * - Initializes FederationNode from config
 * - Starts the FederationTransport (listen + outbound connections)
 * - Registers federation tools into the Agent tool chain
 * - Attaches WS route on the Gateway HTTP server
 * - Sets up isolated Federation Sessions for inbound chat
 * - Exposes Gateway RPC methods for federation management
 *
 * @module federation/gateway-integration
 */

import type http from "node:http";
import type { GatewayRequestHandlers } from "../gateway/server-methods/types.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { FederationNode } from "./client.js";
import { formatPeerId } from "./crypto.js";
import { createFederationTools } from "./tools.js";
import { FederationTransport } from "./transport.js";
import {
  type FederationConfig,
  type FederationCapability,
  type PeerEndpoint,
  FEDERATION_SYSTEM_PROMPT,
  FEDERATION_TOOL_ALLOWLIST,
} from "./types.js";
import { registerFederationWebRoutes } from "./web-ui.js";

const log = createSubsystemLogger("federation");

// ─── Types ──────────────────────────────────────────────────

/**
 * Represents an isolated federation chat session for processing
 * inbound messages from a peer. Each conversation gets its own
 * session that does NOT share context with the main Agent session.
 */
type FederationSession = {
  peerId: string;
  peerName: string;
  conversationId: string;
  createdAt: number;
  messageCount: number;
};

/**
 * Options for federation initialization.
 */
export type FederationInitOptions = {
  /** Federation configuration from OpenClaw config */
  config: FederationConfig;
  /**
   * HTTP server(s) to attach the federation WS upgrade handler to.
   * Typically the same server(s) the main Gateway uses.
   */
  httpServers: http.Server[];
  /**
   * Gateway auth token for the Web UI HTTP API.
   * When provided, federation REST endpoints are registered on the
   * first HTTP server and require this token for authorization.
   */
  gatewayToken?: string;
  /**
   * Callback to register tools into the Agent tool chain.
   * The Gateway provides this to inject federation tools alongside
   * built-in tools and plugin tools.
   */
  registerTools?: (
    tools: Array<{
      label: string;
      name: string;
      description: string;
      parameters: unknown;
      execute: (toolCallId: string, args: unknown) => Promise<string>;
    }>,
  ) => void;
  /**
   * Callback to create an isolated Agent session for handling
   * inbound federation chat messages. Returns the Agent's response text.
   *
   * The session MUST:
   * - Use FEDERATION_SYSTEM_PROMPT as the system prompt
   * - Restrict tools to FEDERATION_TOOL_ALLOWLIST
   * - NOT share context with the main session
   */
  createAgentSession?: (params: {
    systemPrompt: string;
    toolAllowlist: readonly string[];
    peerId: string;
    peerName: string;
    conversationId: string;
    text: string;
  }) => Promise<string>;
};

/**
 * Handle returned by initFederation() for lifecycle management.
 */
export type FederationHandle = {
  /** The FederationNode instance */
  node: FederationNode;
  /** The FederationTransport instance (WS connections) */
  transport: FederationTransport;
  /** Active federation sessions */
  sessions: Map<string, FederationSession>;
  /** Gateway RPC handlers to merge into the Gateway handler map */
  gatewayHandlers: GatewayRequestHandlers;
  /** Gracefully shut down federation */
  shutdown: () => Promise<void>;
};

// ─── Federation Session Manager ─────────────────────────────

/**
 * Manages isolated sessions for processing inbound federation chat.
 *
 * Each conversation gets its own session context that:
 * - Uses FEDERATION_SYSTEM_PROMPT
 * - Only allows FEDERATION_TOOL_ALLOWLIST tools
 * - Does NOT share memory/context with the main session
 * - Has a TTL to prevent stale sessions from accumulating
 *
 * Key security invariant: these sessions are completely isolated from
 * the owner's main session. A federation peer cannot access local files,
 * exec commands, or read memory — only the tools in the allowlist.
 */
class FederationSessionManager {
  private readonly sessions = new Map<string, FederationSession>();
  private readonly maxSessionAge = 3_600_000; // 1 hour
  private readonly maxSessions = 100;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    this.cleanupTimer = setInterval(() => this.cleanup(), 300_000); // every 5 min
  }

  /**
   * Get or create a session for a conversation.
   * Tracks message counts and handles capacity management.
   */
  getOrCreate(params: {
    peerId: string;
    peerName: string;
    conversationId: string;
  }): FederationSession {
    const key = this.sessionKey(params.peerId, params.conversationId);
    let session = this.sessions.get(key);

    if (!session) {
      // Evict oldest sessions if at capacity
      if (this.sessions.size >= this.maxSessions) {
        this.evictOldest();
      }

      session = {
        peerId: params.peerId,
        peerName: params.peerName,
        conversationId: params.conversationId,
        createdAt: Date.now(),
        messageCount: 0,
      };
      this.sessions.set(key, session);
      log.info(
        `federation session created: peer=${formatPeerId(params.peerId)} ` +
          `name=${params.peerName} conv=${params.conversationId}`,
      );
    }

    session.messageCount++;
    return session;
  }

  /**
   * Remove a specific session.
   */
  remove(peerId: string, conversationId: string): boolean {
    return this.sessions.delete(this.sessionKey(peerId, conversationId));
  }

  /**
   * Remove all sessions for a peer (e.g., on disconnect or peer removal).
   */
  removeAllForPeer(peerId: string): number {
    let removed = 0;
    for (const [key, session] of this.sessions) {
      if (session.peerId === peerId) {
        this.sessions.delete(key);
        removed++;
      }
    }
    return removed;
  }

  /**
   * List all active sessions (for status reporting).
   */
  listSessions(): FederationSession[] {
    return Array.from(this.sessions.values());
  }

  /**
   * Get the underlying session map (exposed on the handle for external inspection).
   */
  getMap(): Map<string, FederationSession> {
    return this.sessions;
  }

  /**
   * Dispose all sessions and stop the cleanup timer.
   */
  dispose(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.sessions.clear();
  }

  private sessionKey(peerId: string, conversationId: string): string {
    return `${peerId}:${conversationId}`;
  }

  private cleanup(): void {
    const now = Date.now();
    let expired = 0;
    for (const [key, session] of this.sessions) {
      if (now - session.createdAt > this.maxSessionAge) {
        this.sessions.delete(key);
        expired++;
      }
    }
    if (expired > 0) {
      log.info(`federation session cleanup: expired ${expired} stale sessions`);
    }
  }

  private evictOldest(): void {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;
    for (const [key, session] of this.sessions) {
      if (session.createdAt < oldestTime) {
        oldestTime = session.createdAt;
        oldestKey = key;
      }
    }
    if (oldestKey) {
      this.sessions.delete(oldestKey);
      log.info("federation session evicted (capacity limit)");
    }
  }
}

// ─── Gateway RPC Handlers ───────────────────────────────────

/**
 * Create Gateway RPC handlers for federation management.
 *
 * These are registered as Gateway methods accessible via the WS protocol:
 * - federation.status  — Full federation status (identity, peers, sessions)
 * - federation.addPeer — Add a trusted peer (requires operator.admin)
 * - federation.removePeer — Remove a peer (requires operator.admin)
 * - federation.listPeers — List all known peers (read-only)
 */
function createGatewayRpcHandlers(
  node: FederationNode,
  transport: FederationTransport,
  sessionManager: FederationSessionManager,
): GatewayRequestHandlers {
  return {
    // ── federation.status ─────────────────────────────────
    "federation.status": async ({ respond }) => {
      const status = node.getStatus();
      const sessions = sessionManager.listSessions();
      const connections = transport.getConnectionInfo();

      respond({
        ok: true,
        status,
        transport: {
          activeConnections: transport.activeConnectionCount,
          connections: connections.map((c) => ({
            peerId: formatPeerId(c.peerId),
            peerName: c.peerName,
            phase: c.phase,
            direction: c.outbound ? "outbound" : "inbound",
            connectedAt: new Date(c.connectedAt).toISOString(),
          })),
        },
        activeSessions: sessions.length,
        sessions: sessions.map((s) => ({
          peerId: formatPeerId(s.peerId),
          peerName: s.peerName,
          conversationId: s.conversationId,
          messageCount: s.messageCount,
          createdAt: new Date(s.createdAt).toISOString(),
        })),
      });
    },

    // ── federation.addPeer ────────────────────────────────
    "federation.addPeer": async ({ params, client, respond }) => {
      // Verify owner-level auth
      const scopes = client?.connect?.scopes ?? [];
      if (!scopes.includes("operator.admin")) {
        respond({ ok: false, error: "Requires operator.admin scope" });
        return;
      }

      const publicKey = params.publicKey as string | undefined;
      const name = params.name as string | undefined;
      const endpoint = params.endpoint as PeerEndpoint | undefined;

      if (!publicKey || !name || !endpoint) {
        respond({
          ok: false,
          error: "Missing required params: publicKey, name, endpoint",
        });
        return;
      }

      const capabilities = (params.capabilities as FederationCapability[] | undefined) ?? ["chat"];

      try {
        const { createCapabilityGrant, derivePeerIdFromPublicKey } = await import("./crypto.js");

        const peerId = derivePeerIdFromPublicKey(publicKey);
        const grant = createCapabilityGrant(node.identity, {
          grantee: peerId,
          capabilities,
          rateLimit: { maxMessagesPerMinute: 10, maxMessagesPerHour: 100 },
        });

        node.trustStore.addDirectPeer({
          identity: { peerId, publicKeyPem: publicKey, name },
          endpoint,
          grant,
        });

        log.info(`federation peer added: ${name} (${formatPeerId(peerId)})`);

        // If the peer has a wsUrl, try to connect immediately
        if (endpoint.wsUrl) {
          transport.connectToPeer(endpoint);
        }

        respond({
          ok: true,
          peer: {
            peerId: formatPeerId(peerId),
            name,
            capabilities,
          },
        });
      } catch (err) {
        respond({ ok: false, error: `Failed to add peer: ${String(err)}` });
      }
    },

    // ── federation.removePeer ─────────────────────────────
    "federation.removePeer": async ({ params, client, respond }) => {
      const scopes = client?.connect?.scopes ?? [];
      if (!scopes.includes("operator.admin")) {
        respond({ ok: false, error: "Requires operator.admin scope" });
        return;
      }

      const peerId = params.peerId as string | undefined;
      if (!peerId) {
        respond({ ok: false, error: "Missing required param: peerId" });
        return;
      }

      // Support both full and short peerId lookups
      const allPeers = node.trustStore.listPeers();
      const match = allPeers.find(
        (p) => p.identity.peerId === peerId || formatPeerId(p.identity.peerId) === peerId,
      );

      if (!match) {
        respond({ ok: false, error: `Peer not found: ${peerId}` });
        return;
      }

      const fullPeerId = match.identity.peerId;
      const peerName = match.identity.name;

      // Disconnect if connected
      node.disconnectPeer(fullPeerId);

      // Remove from trust store
      const removed = node.trustStore.removePeer(fullPeerId);

      // Clean up sessions for this peer
      const sessionsRemoved = sessionManager.removeAllForPeer(fullPeerId);

      log.info(
        `federation peer removed: ${peerName} (${formatPeerId(fullPeerId)}), ` +
          `sessions cleaned: ${sessionsRemoved}`,
      );

      respond({
        ok: true,
        removed,
        peer: { peerId: formatPeerId(fullPeerId), name: peerName },
        sessionsRemoved,
      });
    },

    // ── federation.listPeers ──────────────────────────────
    "federation.listPeers": async ({ respond }) => {
      const peers = node.trustStore.listPeers().map((peer) => ({
        peerId: formatPeerId(peer.identity.peerId),
        name: peer.identity.name,
        trust: peer.trust,
        connected: peer.connected,
        endpoint: peer.endpoint,
        capabilities: peer.grantedCapabilities.capabilities,
        lastSeenAt: peer.lastSeenAt ? new Date(peer.lastSeenAt).toISOString() : null,
        addedAt: new Date(peer.addedAt).toISOString(),
      }));

      respond({
        ok: true,
        thisInstance: {
          peerId: formatPeerId(node.identity.peerId),
          name: node.identity.name,
        },
        peers,
        summary: {
          total: peers.length,
          connected: peers.filter((p) => p.connected).length,
          trusted: peers.filter((p) => p.trust === "direct" || p.trust === "vouched").length,
        },
      });
    },
  };
}

// ─── Main Initialization ────────────────────────────────────

/**
 * Initialize the Federation module and integrate it with the Gateway.
 *
 * Call this during Gateway startup. If federation is not enabled in config,
 * returns null immediately.
 *
 * Integration points:
 * 1. **FederationNode** — Created from config, manages identity and trust
 * 2. **FederationTransport** — WS server attached to Gateway HTTP server(s),
 *    handles handshakes, keepalives, and message routing
 * 3. **Federation Tools** — Registered into Agent tool chain for outbound chat
 * 4. **Chat Handler** — Isolated sessions for inbound messages
 * 5. **Gateway RPCs** — Management methods for the Gateway WS API
 *
 * @example
 * ```ts
 * const federation = await initFederation({
 *   config: cfg.federation ?? getDefaultFederationConfig(),
 *   httpServers,
 *   registerTools: (tools) => agentToolchain.register(tools),
 *   createAgentSession: async (params) => {
 *     const session = createIsolatedSession({
 *       systemPrompt: params.systemPrompt,
 *       toolAllowlist: params.toolAllowlist,
 *     });
 *     return session.run(params.text);
 *   },
 * });
 *
 * if (federation) {
 *   Object.assign(extraHandlers, federation.gatewayHandlers);
 * }
 * ```
 */
export async function initFederation(
  opts: FederationInitOptions,
): Promise<FederationHandle | null> {
  const { config } = opts;

  // ── Guard: federation disabled ──────────────────────────
  if (!config || !config.enabled) {
    log.info("federation disabled in config, skipping initialization");
    return null;
  }

  log.info(
    `federation initializing: instance="${config.instanceName}" ` +
      `peers=${config.trustedPeers?.length ?? 0} ` +
      `introductions=${config.allowIntroductions ? "on" : "off"}`,
  );

  // ── Step 1: Create FederationNode ───────────────────────
  const node = new FederationNode(config);
  log.info(
    `federation identity loaded: id=${formatPeerId(node.identity.peerId)} ` +
      `name=${node.identity.name}`,
  );

  // ── Step 2: Create session manager ──────────────────────
  const sessionManager = new FederationSessionManager();

  // ── Step 3: Register chat handler ───────────────────────
  // This handler is invoked when a verified peer sends a chat message.
  // It creates an isolated Agent session with restricted tools and
  // the federation system prompt. The session does NOT have access to
  // files, exec, memory, or any owner-private resources.
  node.onChat(async ({ peerId, peerName, conversationId, text }) => {
    log.info(
      `federation chat from ${peerName} (${formatPeerId(peerId)}): ` +
        `conv=${conversationId} len=${text.length}`,
    );

    // Track the session
    const session = sessionManager.getOrCreate({ peerId, peerName, conversationId });

    // If the host provided an agent session factory, use it
    if (opts.createAgentSession) {
      try {
        const response = await opts.createAgentSession({
          systemPrompt: FEDERATION_SYSTEM_PROMPT,
          toolAllowlist: FEDERATION_TOOL_ALLOWLIST,
          peerId,
          peerName,
          conversationId,
          text,
        });
        log.info(
          `federation chat response to ${peerName}: ` +
            `conv=${conversationId} len=${response.length} msgs=${session.messageCount}`,
        );
        return response;
      } catch (err) {
        log.error(`federation agent session error: ${String(err)}`);
        return "I'm sorry, I encountered an error processing your message. Please try again.";
      }
    }

    // Fallback: no agent session factory provided
    return (
      `Hello from ${node.identity.name}! I received your message but my Agent ` +
      `session handler isn't configured yet. The federation link is working though!`
    );
  });

  // ── Step 4: Register event handler for logging ──────────
  node.onEvent((event, data) => {
    log.info(`federation event: ${event} ${JSON.stringify(data)}`);
  });

  // ── Step 5: Create and start transport ──────────────────
  const transport = new FederationTransport(node);

  // Attach to all Gateway HTTP servers
  // The transport handles the /federation WS path and leaves other
  // upgrade requests for the main Gateway WS handler.
  for (const httpServer of opts.httpServers) {
    transport.startServer(httpServer);
  }

  log.info("federation transport started");

  // Listen for transport events
  transport.on("peer.connected", ({ peerId, peerName }: { peerId: string; peerName: string }) => {
    log.info(`federation peer connected: ${peerName} (${formatPeerId(peerId)})`);
  });

  transport.on(
    "peer.disconnected",
    ({ peerId, peerName }: { peerId: string; peerName: string }) => {
      log.info(`federation peer disconnected: ${peerName} (${formatPeerId(peerId)})`);
      // Note: sessions are kept alive across reconnects.
      // They'll expire via the session manager's TTL cleanup.
    },
  );

  // ── Step 6: Register federation tools ───────────────────
  if (opts.registerTools) {
    const tools = createFederationTools(node);
    opts.registerTools(tools);
    log.info(`federation tools registered: ${tools.map((t) => t.name).join(", ")}`);
  }

  // ── Step 7: Create Gateway RPC handlers ─────────────────
  const gatewayHandlers = createGatewayRpcHandlers(node, transport, sessionManager);
  log.info(`federation RPC methods registered: ${Object.keys(gatewayHandlers).join(", ")}`);

  // ── Step 8: Connect to known peers ──────────────────────
  // Delay slightly to allow the Gateway to finish binding.
  // The transport handles reconnection with exponential backoff.
  setTimeout(() => {
    transport.connectToAllPeers();
  }, 2_000);

  // ── Step 9: Register Web UI HTTP routes ─────────────────
  // Provides REST endpoints for managing federation from a web UI.
  // Requires a gateway auth token to be set.
  if (opts.gatewayToken && opts.httpServers.length > 0) {
    registerFederationWebRoutes({
      server: opts.httpServers[0],
      federationNode: node,
      config,
      gatewayToken: opts.gatewayToken,
    });
    log.info("federation web UI routes registered");
  }

  // ── Done ────────────────────────────────────────────────
  log.info("federation initialization complete");

  return {
    node,
    transport,
    sessions: sessionManager.getMap(),
    gatewayHandlers,
    shutdown: async () => {
      log.info("federation shutting down...");
      sessionManager.dispose();
      await transport.shutdown();
      log.info("federation shutdown complete");
    },
  };
}

/**
 * Default federation config for when the OpenClaw config has no
 * `federation` section. Ensures initFederation() returns null safely.
 */
export function getDefaultFederationConfig(): FederationConfig {
  return {
    enabled: false,
    instanceName: "openclaw",
    defaultRateLimit: {
      maxMessagesPerMinute: 10,
      maxMessagesPerHour: 100,
      maxMessagesPerDay: 500,
    },
    allowIntroductions: false,
    maxTrustDepth: 1,
  };
}
