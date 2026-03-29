/**
 * Federation Transport — WebSocket bidirectional communication layer
 *
 * Manages the real-time WS connections between federation peers:
 * - Listens on `/federation` path for incoming WS upgrade requests
 * - Initiates outbound connections to known peers
 * - Automatic reconnection with exponential backoff (max 60s)
 * - Heartbeat ping/pong (30s interval, 10s timeout)
 * - Routes inbound messages through FederationNode handlers
 * - Enforces signature verification on all inbound frames
 *
 * Protocol frame format:
 *   { "v": 1, "type": "signed_message", "data": SignedMessage }
 *
 * Security:
 *   - Only peers present in the trust store are accepted
 *   - Unknown connections are immediately terminated
 *   - TLS is handled by the upstream Gateway (not this layer)
 */

import { EventEmitter } from "node:events";
import http from "node:http";
import type { IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import WebSocket, { WebSocketServer } from "ws";
import { FederationNode } from "./client.js";
import { verifySignedMessage } from "./crypto.js";
import type {
  FederationMessagePayload,
  PeerEndpoint,
  SignedMessage,
  TrustedPeer,
} from "./types.js";
import { FEDERATION_PROTOCOL_VERSION } from "./types.js";

// ─── Constants ──────────────────────────────────────────────

/** Path that the WS server listens on for federation upgrades. */
const WS_PATH = "/federation";

/** Heartbeat ping interval (ms). */
const HEARTBEAT_INTERVAL_MS = 30_000;

/** Time to wait for a pong response before considering connection dead (ms). */
const _HEARTBEAT_TIMEOUT_MS = 10_000;

/** Initial reconnect delay (ms). */
const RECONNECT_BASE_DELAY_MS = 1_000;

/** Maximum reconnect delay (ms). */
const RECONNECT_MAX_DELAY_MS = 60_000;

/** Handshake timeout — if handshake doesn't complete within this window, drop (ms). */
const HANDSHAKE_TIMEOUT_MS = 15_000;

/** Maximum inbound frame size (256 KB — signed JSON should never be this large). */
const MAX_FRAME_SIZE_BYTES = 256 * 1024;

/** Current protocol version. */
const PROTOCOL_VERSION = FEDERATION_PROTOCOL_VERSION; // 1

// ─── Protocol Frame ─────────────────────────────────────────

type FrameType = "signed_message";

interface ProtocolFrame {
  /** Protocol version. Must equal PROTOCOL_VERSION. */
  v: number;
  /** Frame type. */
  type: FrameType;
  /** Payload — a SignedMessage. */
  data: SignedMessage;
}

// ─── Per-Connection State ───────────────────────────────────

const enum ConnPhase {
  /** WS is open but mutual auth hasn't completed yet. */
  Handshaking = 0,
  /** Fully authenticated — messages can flow. */
  Ready = 1,
  /** Closing / closed. */
  Closed = 2,
}

interface PeerConnection {
  /** Underlying WebSocket. */
  ws: WebSocket;
  /** Current lifecycle phase. */
  phase: ConnPhase;
  /** Resolved peerId (known after first verified message or after handshake). */
  peerId: string | null;
  /** Direction: did *we* initiate? */
  outbound: boolean;
  /** Heartbeat interval handle. */
  heartbeatTimer: ReturnType<typeof setInterval> | null;
  /** true while we are awaiting a pong reply. */
  awaitingPong: boolean;
  /** Handshake timeout handle. */
  handshakeTimer: ReturnType<typeof setTimeout> | null;
  /** Reconnect attempt counter (outbound only). */
  reconnectAttempt: number;
  /** Reconnect timer handle (outbound only, set after disconnect). */
  reconnectTimer: ReturnType<typeof setTimeout> | null;
  /** The endpoint we're connecting to (outbound only). */
  endpoint: PeerEndpoint | null;
  /** Timestamp of connection establishment. */
  connectedAt: number;
}

// ─── Logging helper ─────────────────────────────────────────

type LogLevel = "debug" | "info" | "warn" | "error";

function log(level: LogLevel, msg: string, meta?: Record<string, unknown>): void {
  const prefix = `[federation:transport]`;
  const metaStr = meta ? ` ${JSON.stringify(meta)}` : "";
  switch (level) {
    case "debug":
      // Only uncomment during development:
      // console.debug(`${prefix} ${msg}${metaStr}`);
      break;
    case "info":
      console.log(`${prefix} ${msg}${metaStr}`);
      break;
    case "warn":
      console.warn(`${prefix} ${msg}${metaStr}`);
      break;
    case "error":
      console.error(`${prefix} ${msg}${metaStr}`);
      break;
  }
}

// ─── FederationTransport ────────────────────────────────────

export class FederationTransport extends EventEmitter {
  private readonly node: FederationNode;

  /** WS server (created by startServer). */
  private wss: WebSocketServer | null = null;

  /** HTTP server we attached to (so we can detach on shutdown). */
  private httpServer: http.Server | null = null;

  /**
   * Active connections keyed by peerId.
   * For inbound connections the key is set once the first signed message reveals the sender.
   * For outbound connections the key is set from the trust store before connecting.
   */
  private readonly connections = new Map<string, PeerConnection>();

  /**
   * Inbound connections that have not yet been identified (no peerId yet).
   * Stored by a temporary opaque key so we can evict on timeout.
   */
  private readonly pendingInbound = new Map<string, PeerConnection>();

  /** Counter for generating temporary keys. */
  private tmpKeySeq = 0;

  /** Whether the transport has been shut down. */
  private destroyed = false;

  constructor(node: FederationNode) {
    super();
    this.node = node;
  }

  // ─── Server ─────────────────────────────────────────────

  /**
   * Start the WS server on the given HTTP server, listening at `/federation`.
   * Typically called with the Gateway's existing HTTP server.
   */
  startServer(server: http.Server): void {
    if (this.wss) {
      log("warn", "Server already started — ignoring duplicate call");
      return;
    }

    this.httpServer = server;

    this.wss = new WebSocketServer({
      noServer: true,
      maxPayload: MAX_FRAME_SIZE_BYTES,
    });

    // Handle upgrade requests on the `/federation` path.
    server.on("upgrade", this.handleUpgrade);

    this.wss.on("error", (err) => {
      log("error", "WSS error", { error: String(err) });
    });

    log("info", `Federation WS server listening on path ${WS_PATH}`);
    this.emit("server.started");
  }

  /**
   * Upgrade handler — attached to the HTTP server's 'upgrade' event.
   */
  private handleUpgrade = (request: IncomingMessage, socket: Duplex, head: Buffer): void => {
    // Only handle requests to our path.
    const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
    if (url.pathname !== WS_PATH) {
      return;
    } // Let other handlers deal with it.

    if (!this.wss) {
      socket.destroy();
      return;
    }

    this.wss.handleUpgrade(request, socket, head, (ws) => {
      this.onInboundConnection(ws, request);
    });
  };

  /**
   * Handle a newly accepted inbound WS connection.
   * At this point we don't know who the peer is yet — the first signed
   * message will reveal the senderId which we can look up in the trust store.
   */
  private onInboundConnection(ws: WebSocket, _request: IncomingMessage): void {
    const tmpKey = `_inbound_${++this.tmpKeySeq}`;

    const conn: PeerConnection = {
      ws,
      phase: ConnPhase.Handshaking,
      peerId: null,
      outbound: false,
      heartbeatTimer: null,
      awaitingPong: false,
      handshakeTimer: null,
      reconnectAttempt: 0,
      reconnectTimer: null,
      endpoint: null,
      connectedAt: Date.now(),
    };

    this.pendingInbound.set(tmpKey, conn);

    // Set a handshake timeout — if we don't identify the peer in time, drop.
    conn.handshakeTimer = setTimeout(() => {
      if (conn.phase === ConnPhase.Handshaking) {
        log("warn", "Inbound connection handshake timed out — closing", { tmpKey });
        this.closeConnection(conn, tmpKey);
      }
    }, HANDSHAKE_TIMEOUT_MS);

    this.wireSocketEvents(ws, conn, tmpKey);

    log("info", "Inbound WS connection accepted (awaiting identification)");
  }

  // ─── Client (outbound) ─────────────────────────────────

  /**
   * Initiate an outbound connection to a peer.
   * The peer must already exist in the trust store.
   */
  connectToPeer(endpoint: PeerEndpoint): void {
    if (this.destroyed) {
      return;
    }

    const wsUrl = endpoint.wsUrl;
    if (!wsUrl) {
      log("warn", "Cannot connect — no wsUrl in endpoint", { endpoint });
      return;
    }

    // Find the peer in the trust store that matches this endpoint.
    const peer = this.findPeerByEndpoint(endpoint);
    if (!peer) {
      log("warn", "Cannot connect — peer not found in trust store for endpoint", { wsUrl });
      return;
    }

    const peerId = peer.identity.peerId;

    // Don't double-connect.
    const existing = this.connections.get(peerId);
    if (existing && existing.phase !== ConnPhase.Closed) {
      log("debug", "Already connected/connecting to peer — skipping", { peerId });
      return;
    }

    this.doConnect(peer, endpoint, 0);
  }

  /**
   * Connect to all known peers that have a wsUrl.
   * Typically called at startup.
   */
  connectToAllPeers(): void {
    for (const peer of this.node.trustStore.listPeers()) {
      if (peer.endpoint.wsUrl) {
        this.connectToPeer(peer.endpoint);
      }
    }
  }

  /**
   * Internal: create a WebSocket to the given peer endpoint.
   */
  private doConnect(peer: TrustedPeer, endpoint: PeerEndpoint, attempt: number): void {
    if (this.destroyed) {
      return;
    }

    const wsUrl = endpoint.wsUrl!;
    const peerId = peer.identity.peerId;

    log("info", `Connecting to peer ${peer.identity.name}`, {
      peerId: peerId.slice(0, 12) + "…",
      wsUrl,
      attempt,
    });

    let ws: WebSocket;
    // Ensure the WS URL targets the federation path.
    const fedUrl = new URL(WS_PATH, wsUrl.replace(/\/?$/, "/")).href;

    try {
      ws = new WebSocket(fedUrl, {
        maxPayload: MAX_FRAME_SIZE_BYTES,
        handshakeTimeout: HANDSHAKE_TIMEOUT_MS,
        headers: {
          "X-Federation-Protocol": String(PROTOCOL_VERSION),
        },
      });
    } catch (err) {
      log("error", "Failed to create WS", { error: String(err) });
      this.scheduleReconnect(peerId, endpoint, attempt);
      return;
    }

    const conn: PeerConnection = {
      ws,
      phase: ConnPhase.Handshaking,
      peerId,
      outbound: true,
      heartbeatTimer: null,
      awaitingPong: false,
      handshakeTimer: null,
      reconnectAttempt: attempt,
      reconnectTimer: null,
      endpoint,
      connectedAt: Date.now(),
    };

    // Replace any stale entry.
    this.connections.set(peerId, conn);

    ws.on("open", () => {
      log("info", `WS open to peer ${peer.identity.name}`);

      // Set a handshake timeout.
      conn.handshakeTimer = setTimeout(() => {
        if (conn.phase === ConnPhase.Handshaking) {
          log("warn", "Outbound handshake timed out — closing", { peerId });
          this.closeConnection(conn, peerId);
        }
      }, HANDSHAKE_TIMEOUT_MS);

      // Initiate handshake: send Hello.
      this.sendHello(conn);
    });

    this.wireSocketEvents(ws, conn, peerId);
  }

  // ─── Socket Event Wiring ───────────────────────────────

  /**
   * Attach message / close / error / pong handlers to a WebSocket.
   * `key` is either the peerId (outbound) or a temporary key (inbound-pending).
   */
  private wireSocketEvents(ws: WebSocket, conn: PeerConnection, key: string): void {
    ws.on("message", (raw: Buffer | string) => {
      void this.onMessage(conn, key, raw);
    });

    ws.on("pong", () => {
      conn.awaitingPong = false;
    });

    ws.on("close", (code, reason) => {
      log("info", "WS closed", {
        key: key.startsWith("_inbound") ? key : key.slice(0, 12) + "…",
        code,
        reason: reason?.toString() ?? "",
      });
      this.onDisconnect(conn, key);
    });

    ws.on("error", (err) => {
      log("warn", "WS error", {
        key: key.startsWith("_inbound") ? key : key.slice(0, 12) + "…",
        error: String(err),
      });
      // The 'close' event will follow; cleanup happens there.
    });
  }

  // ─── Handshake Flow ────────────────────────────────────

  /**
   * Send Hello (Step 1 — outbound initiator).
   */
  private sendHello(conn: PeerConnection): void {
    const helloMsg = this.node.createHello();
    this.sendFrame(conn, helloMsg);
    log("debug", "Sent Hello", { peerId: conn.peerId ?? "?" });
  }

  /**
   * Route a handshake or post-handshake message through the FederationNode.
   */
  private async handlePayload(
    conn: PeerConnection,
    key: string,
    signedMsg: SignedMessage,
    payload: FederationMessagePayload,
  ): Promise<void> {
    const type = payload.type;

    switch (type) {
      // ── Inbound Hello (we are the responder) ─────────
      case "hello": {
        const result = this.node.handleHello(signedMsg);
        if (!result.ok) {
          log("warn", `Hello rejected: ${result.error}`, { senderId: signedMsg.senderId });
          this.closeConnection(conn, key);
          return;
        }

        // Now we know who the peer is — promote from pendingInbound.
        const peerId = signedMsg.senderId;
        this.promoteInbound(conn, key, peerId);
        this.sendFrame(conn, result.response);
        log("info", `Sent HelloAck to ${peerId.slice(0, 12)}…`);
        break;
      }

      // ── HelloAck (we are the initiator, Step 3) ──────
      case "hello.ack": {
        const result = this.node.handleHelloAck(signedMsg);
        if (!result.ok) {
          log("warn", `HelloAck rejected: ${result.error}`, { senderId: signedMsg.senderId });
          this.closeConnection(conn, key);
          return;
        }

        this.sendFrame(conn, result.response);
        log("info", `Sent HelloVerified to ${result.peerId.slice(0, 12)}…`);

        // Handshake complete on initiator side.
        this.onHandshakeComplete(conn, result.peerId);
        break;
      }

      // ── HelloVerified (we are the responder, final step) ──
      case "hello.verified": {
        const result = this.node.handleHelloVerified(signedMsg);
        if (!result.ok) {
          log("warn", `HelloVerified rejected: ${result.error}`, { senderId: signedMsg.senderId });
          this.closeConnection(conn, key);
          return;
        }

        // Handshake complete on responder side.
        this.onHandshakeComplete(conn, signedMsg.senderId);
        break;
      }

      // ── Chat message ─────────────────────────────────
      case "chat": {
        if (conn.phase !== ConnPhase.Ready) {
          log("warn", "Chat message received before handshake complete — ignoring");
          return;
        }

        const chatResult = await this.node.handleChatMessage(signedMsg);
        if (chatResult.ok) {
          this.sendFrame(conn, chatResult.response);
        } else {
          log("warn", `Chat handling failed: ${chatResult.error}`, { peerId: conn.peerId });
        }
        break;
      }

      // ── Chat response ────────────────────────────────
      case "chat.response": {
        if (conn.phase !== ConnPhase.Ready) {
          return;
        }
        // Emit for whoever is awaiting the reply.
        this.emit("chat.response", {
          peerId: signedMsg.senderId,
          payload,
        });
        break;
      }

      // ── Application-level ping/pong (distinct from WS-level) ──
      case "ping": {
        // Reply with pong through the federation node so it's signed.
        const pongPayload: FederationMessagePayload = { type: "pong", data: { ts: Date.now() } };
        const { createSignedMessage } = await import("./crypto.js");
        const pong = createSignedMessage(this.node.identity, pongPayload);
        this.sendFrame(conn, pong);
        break;
      }

      case "pong": {
        // Application-level pong — mark heartbeat as answered + update last seen.
        conn.awaitingPong = false;
        if (conn.peerId) {
          this.node.trustStore.getPeer(conn.peerId);
          // lastSeenAt updated by trustStore.setConnected already.
        }
        break;
      }

      // ── Capability grant / revoke / introduce ────────
      case "capability.grant":
      case "capability.revoke":
      case "introduce": {
        // Forward to event bus for higher layers to handle.
        this.emit("message", { peerId: signedMsg.senderId, type, payload });
        break;
      }

      default:
        log("warn", `Unknown message type: ${String(type)}`, { senderId: signedMsg.senderId });
    }
  }

  // ─── Frame Encoding / Decoding ─────────────────────────

  /**
   * Send a signed message wrapped in the protocol frame.
   */
  private sendFrame(conn: PeerConnection, signedMsg: SignedMessage): boolean {
    if (conn.ws.readyState !== WebSocket.OPEN) {
      log("debug", "Cannot send — socket not open");
      return false;
    }

    const frame: ProtocolFrame = {
      v: PROTOCOL_VERSION,
      type: "signed_message",
      data: signedMsg,
    };

    try {
      conn.ws.send(JSON.stringify(frame));
      return true;
    } catch (err) {
      log("error", "Failed to send frame", { error: String(err) });
      return false;
    }
  }

  /**
   * Decode and validate an incoming raw WS message.
   * Returns the frame or null on error.
   */
  private decodeFrame(raw: Buffer | string): ProtocolFrame | null {
    let text: string;
    if (Buffer.isBuffer(raw)) {
      text = raw.toString("utf8");
    } else if (typeof raw === "string") {
      text = raw;
    } else {
      log("warn", "Received non-text WS frame — ignoring");
      return null;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      log("warn", "Received invalid JSON frame — ignoring");
      return null;
    }

    const frame = parsed as Record<string, unknown>;

    // Validate protocol version.
    if (typeof frame.v !== "number" || frame.v !== PROTOCOL_VERSION) {
      log("warn", `Unsupported protocol version: ${String(frame.v)}`);
      return null;
    }

    // Validate frame type.
    if (frame.type !== "signed_message") {
      log("warn", `Unknown frame type: ${String(frame.type)}`);
      return null;
    }

    // Basic structure check on data.
    const data = frame.data as Record<string, unknown> | undefined;
    if (
      !data ||
      typeof data.payload !== "string" ||
      typeof data.signature !== "string" ||
      typeof data.senderId !== "string" ||
      typeof data.seq !== "number" ||
      typeof data.timestamp !== "number"
    ) {
      log("warn", "Malformed SignedMessage in frame");
      return null;
    }

    return frame as unknown as ProtocolFrame;
  }

  // ─── Message Handling ──────────────────────────────────

  /**
   * Called for every raw WS message.
   */
  private async onMessage(conn: PeerConnection, key: string, raw: Buffer | string): Promise<void> {
    if (conn.phase === ConnPhase.Closed) {
      return;
    }

    // Decode the protocol frame.
    const frame = this.decodeFrame(raw);
    if (!frame) {
      // Already logged in decodeFrame.
      return;
    }

    const signedMsg = frame.data;

    // ── Resolve peer public key for verification ──

    // During handshake on inbound connections we may not know the peerId yet.
    // The first message (Hello) carries the sender identity, so we look it
    // up in the trust store by senderId.
    const senderId = signedMsg.senderId;
    const peer = this.node.trustStore.getPeer(senderId);

    if (!peer) {
      log("warn", `Received message from unknown peer ${senderId.slice(0, 12)}… — closing`);
      this.closeConnection(conn, key);
      return;
    }

    // ── Signature verification (mandatory for all messages) ──

    const verification = verifySignedMessage(peer.identity.publicKeyPem, signedMsg);
    if (!verification.valid) {
      log("warn", `Signature verification failed: ${verification.error}`, {
        senderId: senderId.slice(0, 12) + "…",
      });
      this.closeConnection(conn, key);
      return;
    }

    // Update last seen timestamp.
    this.node.trustStore.setConnected(senderId, peer.connected);
    const peerObj = this.node.trustStore.getPeer(senderId);
    if (peerObj) {
      peerObj.lastSeenAt = Date.now();
    }

    // ── Dispatch to handler ──

    try {
      await this.handlePayload(conn, key, signedMsg, verification.payload!);
    } catch (err) {
      log("error", "Unhandled error in payload handler", {
        senderId: senderId.slice(0, 12) + "…",
        error: String(err),
      });
    }
  }

  // ─── Handshake Lifecycle ───────────────────────────────

  /**
   * Promote an inbound connection from pendingInbound to the connections map
   * now that we know the peerId.
   */
  private promoteInbound(conn: PeerConnection, tmpKey: string, peerId: string): void {
    this.pendingInbound.delete(tmpKey);
    conn.peerId = peerId;

    // If there's already an active outbound connection to this peer, we have
    // a conflict. The tiebreaker: the side whose peerId is lexicographically
    // smaller keeps the *outbound* connection; the other side keeps inbound.
    const existing = this.connections.get(peerId);
    if (existing && existing.phase !== ConnPhase.Closed && existing !== conn) {
      const ourId = this.node.identity.peerId;
      if (ourId < peerId) {
        // We keep our outbound. Close this inbound duplicate.
        log("info", "Duplicate connection tiebreak: keeping outbound", {
          peerId: peerId.slice(0, 12) + "…",
        });
        conn.ws.close(4001, "duplicate-connection");
        return;
      } else {
        // We keep the inbound. Close the outbound.
        log("info", "Duplicate connection tiebreak: keeping inbound", {
          peerId: peerId.slice(0, 12) + "…",
        });
        this.closeConnection(existing, peerId);
      }
    }

    this.connections.set(peerId, conn);
  }

  /**
   * Called when the handshake successfully completes on either side.
   */
  private onHandshakeComplete(conn: PeerConnection, peerId: string): void {
    if (conn.handshakeTimer) {
      clearTimeout(conn.handshakeTimer);
      conn.handshakeTimer = null;
    }

    conn.phase = ConnPhase.Ready;
    conn.peerId = peerId;
    conn.reconnectAttempt = 0; // Reset backoff on success.

    // Ensure it's in the connections map.
    this.connections.set(peerId, conn);

    // Mark peer as connected in trust store.
    this.node.trustStore.setConnected(peerId, true);

    // Start heartbeat.
    this.startHeartbeat(conn);

    const peerName = this.node.trustStore.getPeer(peerId)?.identity.name ?? peerId.slice(0, 12);
    log("info", `✅ Handshake complete with ${peerName}`);
    this.emit("peer.connected", { peerId, peerName });
  }

  // ─── Heartbeat ─────────────────────────────────────────

  /**
   * Start WS-level ping/pong heartbeat for a connection.
   */
  private startHeartbeat(conn: PeerConnection): void {
    this.stopHeartbeat(conn);

    conn.heartbeatTimer = setInterval(async () => {
      if (conn.ws.readyState !== WebSocket.OPEN) {
        this.stopHeartbeat(conn);
        return;
      }

      if (conn.awaitingPong) {
        // Previous pong never arrived — connection is dead.
        log("warn", "Heartbeat timeout — peer did not respond to ping", {
          peerId: conn.peerId?.slice(0, 12) ?? "?",
        });
        this.closeConnection(conn, conn.peerId ?? "");
        return;
      }

      conn.awaitingPong = true;
      try {
        // Use application-level ping (text frame) instead of WS-level ping.
        // ALB/reverse proxies may not forward WS ping frames, causing spurious disconnects.
        const { createSignedMessage } = await import("./crypto.js");
        const pingPayload: FederationMessagePayload = { type: "ping", data: { ts: Date.now() } };
        const ping = createSignedMessage(this.node.identity, pingPayload);
        this.sendFrame(conn, ping);
      } catch {
        // Socket may have errored between readyState check and send.
        this.closeConnection(conn, conn.peerId ?? "");
      }
    }, HEARTBEAT_INTERVAL_MS);
  }

  /**
   * Stop the heartbeat timer for a connection.
   */
  private stopHeartbeat(conn: PeerConnection): void {
    if (conn.heartbeatTimer) {
      clearInterval(conn.heartbeatTimer);
      conn.heartbeatTimer = null;
    }
    conn.awaitingPong = false;
  }

  // ─── Disconnect & Reconnect ────────────────────────────

  /**
   * Handle a WS close event (or forceful close from our side).
   */
  private onDisconnect(conn: PeerConnection, key: string): void {
    const peerId = conn.peerId;

    // Clean up timers.
    this.stopHeartbeat(conn);
    if (conn.handshakeTimer) {
      clearTimeout(conn.handshakeTimer);
      conn.handshakeTimer = null;
    }

    conn.phase = ConnPhase.Closed;

    // Remove from maps.
    this.pendingInbound.delete(key);
    if (peerId) {
      // Only remove from connections if *this* conn is the current one.
      const current = this.connections.get(peerId);
      if (current === conn) {
        this.connections.delete(peerId);
      }

      // Update trust store.
      this.node.trustStore.setConnected(peerId, false);
      this.node.disconnectPeer(peerId);

      const peerName = this.node.trustStore.getPeer(peerId)?.identity.name ?? peerId.slice(0, 12);
      log("info", `Peer disconnected: ${peerName}`);
      this.emit("peer.disconnected", { peerId, peerName });

      // Schedule reconnect for outbound connections.
      if (conn.outbound && conn.endpoint) {
        this.scheduleReconnect(peerId, conn.endpoint, conn.reconnectAttempt);
      }
    }
  }

  /**
   * Close a connection gracefully.
   */
  private closeConnection(conn: PeerConnection, key: string): void {
    if (conn.phase === ConnPhase.Closed) {
      return;
    }
    conn.phase = ConnPhase.Closed;

    try {
      if (conn.ws.readyState === WebSocket.OPEN || conn.ws.readyState === WebSocket.CONNECTING) {
        conn.ws.close(1000, "transport-close");
      }
    } catch {
      // Best effort.
    }

    // onDisconnect will fire from the 'close' event, but call it directly
    // to ensure cleanup if the event never fires (e.g. CONNECTING state).
    this.onDisconnect(conn, key);
  }

  /**
   * Schedule automatic reconnection with exponential backoff.
   */
  private scheduleReconnect(peerId: string, endpoint: PeerEndpoint, previousAttempt: number): void {
    if (this.destroyed) {
      return;
    }

    // Don't reconnect if the peer has been removed from the trust store.
    const peer = this.node.trustStore.getPeer(peerId);
    if (!peer) {
      log("debug", "Peer removed from trust store — not reconnecting", {
        peerId: peerId.slice(0, 12) + "…",
      });
      return;
    }

    const attempt = previousAttempt + 1;
    const delay = Math.min(
      RECONNECT_BASE_DELAY_MS * Math.pow(2, attempt - 1),
      RECONNECT_MAX_DELAY_MS,
    );
    // Add jitter: ±25% of the delay.
    const jitter = delay * 0.25 * (Math.random() * 2 - 1);
    const actualDelay = Math.round(delay + jitter);

    log(
      "info",
      `Scheduling reconnect to ${peer.identity.name} in ${actualDelay}ms (attempt ${attempt})`,
      {
        peerId: peerId.slice(0, 12) + "…",
      },
    );

    const timer = setTimeout(() => {
      if (this.destroyed) {
        return;
      }
      const freshPeer = this.node.trustStore.getPeer(peerId);
      if (!freshPeer) {
        return;
      }

      // Don't reconnect if already connected (e.g. peer reconnected to us).
      const existing = this.connections.get(peerId);
      if (existing && existing.phase !== ConnPhase.Closed) {
        return;
      }

      this.doConnect(freshPeer, endpoint, attempt);
    }, actualDelay);

    // Store the timer so we can cancel on shutdown.
    const existingConn = this.connections.get(peerId);
    if (existingConn) {
      existingConn.reconnectTimer = timer;
    }
  }

  // ─── Public API: Send ──────────────────────────────────

  /**
   * Send a signed message to a specific peer.
   * Returns true if the message was queued for sending.
   */
  sendToPeer(peerId: string, signedMsg: SignedMessage): boolean {
    const conn = this.connections.get(peerId);
    if (!conn || conn.phase !== ConnPhase.Ready) {
      log("debug", "Cannot send — no ready connection to peer", {
        peerId: peerId.slice(0, 12) + "…",
        phase: conn?.phase,
      });
      return false;
    }

    return this.sendFrame(conn, signedMsg);
  }

  /**
   * Send a chat message to a peer and return a promise that resolves
   * with the chat response (or rejects on timeout).
   */
  async sendChat(params: {
    peerId: string;
    text: string;
    conversationId?: string;
    timeoutMs?: number;
  }): Promise<{ text: string; conversationId: string; deferredToOwner: boolean }> {
    const { peerId, text, conversationId, timeoutMs = 60_000 } = params;

    const result = this.node.createChatMessage({ peerId, text, conversationId });
    if (!result.ok) {
      throw new Error(result.error);
    }

    const sent = this.sendToPeer(peerId, result.message);
    if (!sent) {
      throw new Error(`Failed to send chat message to peer ${peerId.slice(0, 12)}…`);
    }

    // Wait for the response.
    return new Promise<{ text: string; conversationId: string; deferredToOwner: boolean }>(
      (resolve, reject) => {
        const timer = setTimeout(() => {
          this.removeListener("chat.response", handler);
          reject(new Error("Chat response timed out"));
        }, timeoutMs);

        const handler = (event: { peerId: string; payload: FederationMessagePayload }) => {
          if (event.peerId !== peerId) {
            return;
          }

          const data = event.payload.data as {
            conversationId: string;
            text: string;
            deferredToOwner: boolean;
          };

          if (data.conversationId !== result.conversationId) {
            return;
          }

          clearTimeout(timer);
          this.removeListener("chat.response", handler);
          resolve({
            text: data.text,
            conversationId: data.conversationId,
            deferredToOwner: data.deferredToOwner,
          });
        };

        this.on("chat.response", handler);
      },
    );
  }

  // ─── Public API: Status ────────────────────────────────

  /**
   * Check if a peer is connected and ready.
   */
  isPeerConnected(peerId: string): boolean {
    const conn = this.connections.get(peerId);
    return conn?.phase === ConnPhase.Ready;
  }

  /**
   * Get the number of active (ready) connections.
   */
  get activeConnectionCount(): number {
    let count = 0;
    for (const conn of this.connections.values()) {
      if (conn.phase === ConnPhase.Ready) {
        count++;
      }
    }
    return count;
  }

  /**
   * Get connection info for all peers.
   */
  getConnectionInfo(): Array<{
    peerId: string;
    peerName: string;
    phase: string;
    outbound: boolean;
    connectedAt: number;
    reconnectAttempt: number;
  }> {
    const result: Array<{
      peerId: string;
      peerName: string;
      phase: string;
      outbound: boolean;
      connectedAt: number;
      reconnectAttempt: number;
    }> = [];

    for (const [peerId, conn] of this.connections) {
      const peer = this.node.trustStore.getPeer(peerId);
      result.push({
        peerId,
        peerName: peer?.identity.name ?? "unknown",
        phase:
          conn.phase === ConnPhase.Ready
            ? "Ready"
            : conn.phase === ConnPhase.Handshaking
              ? "Handshaking"
              : "Closed",
        outbound: conn.outbound,
        connectedAt: conn.connectedAt,
        reconnectAttempt: conn.reconnectAttempt,
      });
    }

    return result;
  }

  // ─── Shutdown ──────────────────────────────────────────

  /**
   * Gracefully shut down all connections and the server.
   */
  async shutdown(): Promise<void> {
    if (this.destroyed) {
      return;
    }
    this.destroyed = true;

    log("info", "Shutting down federation transport…");

    // Cancel all reconnect timers.
    for (const conn of this.connections.values()) {
      if (conn.reconnectTimer) {
        clearTimeout(conn.reconnectTimer);
        conn.reconnectTimer = null;
      }
    }

    // Close all active connections.
    const closePromises: Promise<void>[] = [];

    for (const [_key, conn] of this.connections) {
      closePromises.push(this.gracefulClose(conn));
    }
    for (const [_key, conn] of this.pendingInbound) {
      closePromises.push(this.gracefulClose(conn));
    }

    await Promise.allSettled(closePromises);

    this.connections.clear();
    this.pendingInbound.clear();

    // Detach from HTTP server.
    if (this.httpServer) {
      this.httpServer.removeListener("upgrade", this.handleUpgrade);
      this.httpServer = null;
    }

    // Close the WSS.
    if (this.wss) {
      await new Promise<void>((resolve) => {
        this.wss!.close(() => resolve());
      });
      this.wss = null;
    }

    log("info", "Federation transport shut down");
    this.emit("shutdown");
  }

  /**
   * Gracefully close a single WS with a short drain period.
   */
  private gracefulClose(conn: PeerConnection): Promise<void> {
    return new Promise((resolve) => {
      this.stopHeartbeat(conn);
      if (conn.handshakeTimer) {
        clearTimeout(conn.handshakeTimer);
        conn.handshakeTimer = null;
      }
      if (conn.reconnectTimer) {
        clearTimeout(conn.reconnectTimer);
        conn.reconnectTimer = null;
      }

      conn.phase = ConnPhase.Closed;

      if (conn.ws.readyState === WebSocket.CLOSED || conn.ws.readyState === WebSocket.CLOSING) {
        resolve();
        return;
      }

      const timeout = setTimeout(() => {
        try {
          conn.ws.terminate();
        } catch {
          // Already dead.
        }
        resolve();
      }, 3_000);

      conn.ws.once("close", () => {
        clearTimeout(timeout);
        resolve();
      });

      try {
        conn.ws.close(1001, "transport-shutdown");
      } catch {
        clearTimeout(timeout);
        resolve();
      }
    });
  }

  // ─── Helpers ───────────────────────────────────────────

  /**
   * Find a peer in the trust store that matches the given endpoint.
   */
  private findPeerByEndpoint(endpoint: PeerEndpoint): TrustedPeer | undefined {
    const peers = this.node.trustStore.listPeers();
    return peers.find((p) => {
      if (endpoint.wsUrl && p.endpoint.wsUrl === endpoint.wsUrl) {
        return true;
      }
      if (endpoint.httpUrl && p.endpoint.httpUrl === endpoint.httpUrl) {
        return true;
      }
      if (endpoint.tailnetHostname && p.endpoint.tailnetHostname === endpoint.tailnetHostname) {
        return true;
      }
      return false;
    });
  }
}

// ─── SimplePeerConnection ───────────────────────────────────

/**
 * Connection status for a {@link SimplePeerConnection}.
 */
export type SimplePeerStatus = "connected" | "disconnected" | "connecting";

/**
 * Events emitted by {@link SimplePeerConnection}.
 *
 * - `connected`     — WebSocket is open and authenticated.
 * - `disconnected`  — WebSocket has closed (intentionally or not).
 * - `reconnecting`  — Automatic reconnect is scheduled.
 * - `message`       — A JSON message was received from the peer.
 * - `error`         — An error occurred on the connection.
 */
export interface SimplePeerConnectionEvents {
  connected: [];
  disconnected: [code: number, reason: string];
  reconnecting: [attempt: number, delayMs: number];
  message: [data: unknown];
  error: [err: Error];
}

/**
 * Simplified peer connection using token-based auth.
 *
 * No Ed25519 handshake — authenticates with `Authorization: Bearer <token>`
 * on the WebSocket upgrade request.
 *
 * Features:
 * - Automatic reconnect with exponential backoff (1s → 60s max)
 * - Heartbeat ping every 30s, disconnect after 3 missed pongs
 * - Connection pool safety: only one WS per instance
 *
 * @example
 * ```ts
 * const conn = new SimplePeerConnection({
 *   peerName: "Nova",
 *   endpoint: "wss://nova.example.com/federation",
 *   token: "gw-token-xxx",
 * });
 *
 * conn.on("connected", () => console.log("Connected!"));
 * conn.on("message", (msg) => console.log("Got:", msg));
 *
 * await conn.connect();
 * await conn.send({ type: "chat", text: "Hello from Ark!" });
 * ```
 */
export class SimplePeerConnection extends EventEmitter {
  /** Human-readable peer name. */
  readonly peerName: string;

  /** Peer's WebSocket endpoint URL. */
  readonly endpoint: string;

  /** Auth token for this peer. */
  private readonly token: string;

  /** Active WebSocket instance (null when disconnected). */
  private ws: WebSocket | null = null;

  /** Number of consecutive reconnect attempts since last successful connect. */
  private reconnectAttempts = 0;

  /** Maximum reconnect delay in milliseconds. */
  private maxReconnectDelay = RECONNECT_MAX_DELAY_MS;

  /** Handle for the periodic heartbeat interval. */
  private heartbeatInterval: NodeJS.Timeout | null = null;

  /** Number of consecutive heartbeat pings without a pong reply. */
  private missedPongs = 0;

  /** Maximum missed pongs before considering the connection dead. */
  private readonly maxMissedPongs = 3;

  /** Handle for a pending reconnect timer. */
  private reconnectTimer: NodeJS.Timeout | null = null;

  /** Whether {@link disconnect} was called intentionally (suppresses reconnect). */
  private intentionalClose = false;

  /** Whether this connection has been permanently destroyed. */
  private destroyed = false;

  /** Timestamp (ms) of the last successful pong received. */
  private lastPongAt: number | null = null;

  /** Timestamp (ms) when the current WS connection was established. */
  private connectedAt: number | null = null;

  /** Internal status tracker. */
  private _status: SimplePeerStatus = "disconnected";

  /**
   * Create a new SimplePeerConnection.
   *
   * @param params - Connection parameters.
   * @param params.peerName - Human-readable display name for the peer.
   * @param params.endpoint - WebSocket endpoint URL (wss:// or ws://).
   * @param params.token - Gateway auth token for Bearer authentication.
   */
  constructor(params: { peerName: string; endpoint: string; token: string }) {
    super();
    this.peerName = params.peerName;
    this.endpoint = params.endpoint;
    this.token = params.token;
  }

  // ─── Public Properties ──────────────────────────────────

  /**
   * Current connection status.
   */
  get status(): SimplePeerStatus {
    return this._status;
  }

  /**
   * Estimated latency in milliseconds based on the last heartbeat round-trip.
   * Returns `null` if no pong has been received yet.
   */
  get latencyMs(): number | null {
    if (this.lastPongAt === null || this.connectedAt === null) {
      return null;
    }
    // Approximation: time since last pong vs heartbeat interval.
    // A more accurate measurement would record the ping send time, but this
    // is good enough for monitoring purposes.
    return this.lastPongAt > 0 ? Date.now() - this.lastPongAt : null;
  }

  // ─── Connect ────────────────────────────────────────────

  /**
   * Establish a WebSocket connection to the peer.
   *
   * If already connected or connecting, this is a no-op.
   * The returned promise resolves when the WS is open (not when messages
   * can flow — that depends on the peer accepting the token).
   *
   * @throws {Error} If the connection has been permanently destroyed.
   */
  async connect(): Promise<void> {
    if (this.destroyed) {
      throw new Error(`SimplePeerConnection to "${this.peerName}" has been destroyed`);
    }

    // Prevent duplicate connections (connection pool safety).
    if (this._status === "connected" || this._status === "connecting") {
      log("debug", `Already ${this._status} to simple peer "${this.peerName}" — skipping`);
      return;
    }

    this.intentionalClose = false;
    this._status = "connecting";

    return new Promise<void>((resolve, reject) => {
      let settled = false;

      try {
        this.ws = new WebSocket(this.endpoint, {
          headers: {
            Authorization: `Bearer ${this.token}`,
            "X-Federation-Protocol": String(PROTOCOL_VERSION),
            "X-Federation-Peer-Name": this.peerName,
          },
          maxPayload: MAX_FRAME_SIZE_BYTES,
          handshakeTimeout: HANDSHAKE_TIMEOUT_MS,
        });
      } catch (err) {
        this._status = "disconnected";
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }

      this.ws.on("open", () => {
        if (settled) {
          return;
        }
        settled = true;

        this._status = "connected";
        this.reconnectAttempts = 0;
        this.connectedAt = Date.now();
        this.missedPongs = 0;

        log("info", `✅ Connected to simple peer "${this.peerName}"`);
        this.startHeartbeat();
        this.emit("connected");
        resolve();
      });

      this.ws.on("message", (raw: Buffer | string) => {
        this.onMessage(raw);
      });

      this.ws.on("pong", () => {
        this.missedPongs = 0;
        this.lastPongAt = Date.now();
      });

      this.ws.on("close", (code: number, reason: Buffer) => {
        const reasonStr = reason?.toString() ?? "";

        if (!settled) {
          settled = true;
          this._status = "disconnected";
          reject(new Error(`WS closed before open: code=${code} reason=${reasonStr}`));
        }

        this.onClose(code, reasonStr);
      });

      this.ws.on("error", (err: Error) => {
        log("warn", `WS error for simple peer "${this.peerName}"`, { error: String(err) });
        this.emit("error", err);

        if (!settled) {
          settled = true;
          this._status = "disconnected";
          reject(err);
        }
        // The 'close' event will follow and handle cleanup / reconnect.
      });
    });
  }

  // ─── Disconnect ─────────────────────────────────────────

  /**
   * Gracefully disconnect from the peer.
   *
   * This will NOT trigger automatic reconnection.
   * Call {@link connect} again to re-establish the connection.
   */
  async disconnect(): Promise<void> {
    this.intentionalClose = true;
    this.clearTimers();

    if (!this.ws) {
      this._status = "disconnected";
      return;
    }

    return new Promise<void>((resolve) => {
      const timeout = setTimeout(() => {
        try {
          this.ws?.terminate();
        } catch {
          // Already dead.
        }
        this.ws = null;
        this._status = "disconnected";
        resolve();
      }, 3_000);

      this.ws!.once("close", () => {
        clearTimeout(timeout);
        this.ws = null;
        this._status = "disconnected";
        resolve();
      });

      try {
        if (
          this.ws!.readyState === WebSocket.OPEN ||
          this.ws!.readyState === WebSocket.CONNECTING
        ) {
          this.ws!.close(1000, "intentional-disconnect");
        } else {
          clearTimeout(timeout);
          this.ws = null;
          this._status = "disconnected";
          resolve();
        }
      } catch {
        clearTimeout(timeout);
        this.ws = null;
        this._status = "disconnected";
        resolve();
      }
    });
  }

  /**
   * Permanently destroy this connection. Cannot be reconnected after this.
   */
  async destroy(): Promise<void> {
    this.destroyed = true;
    await this.disconnect();
    this.removeAllListeners();
  }

  // ─── Send ───────────────────────────────────────────────

  /**
   * Send a JSON message to the peer.
   *
   * @param message - Any JSON-serializable object.
   * @throws {Error} If the connection is not in the "connected" state.
   */
  async send(message: object): Promise<void> {
    if (this._status !== "connected" || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error(`Cannot send to simple peer "${this.peerName}" — status: ${this._status}`);
    }

    return new Promise<void>((resolve, reject) => {
      this.ws!.send(JSON.stringify(message), (err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }

  // ─── Heartbeat ──────────────────────────────────────────

  /**
   * Start the heartbeat ping interval.
   * Sends a WS-level ping every 30s. If 3 consecutive pings go
   * unanswered, the connection is considered dead and closed.
   */
  private startHeartbeat(): void {
    this.stopHeartbeat();

    this.heartbeatInterval = setInterval(() => {
      if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
        this.stopHeartbeat();
        return;
      }

      if (this.missedPongs >= this.maxMissedPongs) {
        log(
          "warn",
          `Heartbeat: ${this.missedPongs} missed pongs from "${this.peerName}" — closing`,
        );
        this.ws.close(4002, "heartbeat-timeout");
        return;
      }

      this.missedPongs++;
      try {
        this.ws.ping();
      } catch {
        // Socket already erroring — close event will handle it.
        log("warn", `Failed to send ping to "${this.peerName}"`);
      }
    }, HEARTBEAT_INTERVAL_MS);
  }

  /**
   * Stop the heartbeat interval.
   */
  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
    this.missedPongs = 0;
  }

  // ─── Reconnect ──────────────────────────────────────────

  /**
   * Schedule automatic reconnection with exponential backoff.
   *
   * Delay: 1s × 2^attempt, capped at 60s, with ±25% jitter.
   */
  private scheduleReconnect(): void {
    if (this.destroyed || this.intentionalClose) {
      return;
    }

    this.reconnectAttempts++;
    const baseDelay = Math.min(
      RECONNECT_BASE_DELAY_MS * Math.pow(2, this.reconnectAttempts - 1),
      this.maxReconnectDelay,
    );
    // Add jitter: ±25% of the delay.
    const jitter = baseDelay * 0.25 * (Math.random() * 2 - 1);
    const delay = Math.round(baseDelay + jitter);

    log(
      "info",
      `Scheduling reconnect to "${this.peerName}" in ${delay}ms (attempt ${this.reconnectAttempts})`,
    );

    this.emit("reconnecting", this.reconnectAttempts, delay);

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      if (this.destroyed || this.intentionalClose) {
        return;
      }

      try {
        await this.connect();
      } catch (err) {
        log("warn", `Reconnect attempt ${this.reconnectAttempts} to "${this.peerName}" failed`, {
          error: String(err),
        });
        // connect() failure triggers onClose → scheduleReconnect again.
      }
    }, delay);
  }

  // ─── Internal Event Handlers ────────────────────────────

  /**
   * Handle an incoming WS message.
   */
  private onMessage(raw: Buffer | string): void {
    let text: string;
    if (Buffer.isBuffer(raw)) {
      text = raw.toString("utf8");
    } else {
      text = raw;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      log("warn", `Received invalid JSON from simple peer "${this.peerName}" — ignoring`);
      return;
    }

    this.emit("message", parsed);
  }

  /**
   * Handle a WS close event.
   */
  private onClose(code: number, reason: string): void {
    const wasConnected = this._status === "connected";
    this._status = "disconnected";
    this.ws = null;

    this.stopHeartbeat();

    if (wasConnected) {
      log("info", `Disconnected from simple peer "${this.peerName}" (code=${code})`);
      this.emit("disconnected", code, reason);
    }

    // Auto-reconnect unless intentional or destroyed.
    if (!this.intentionalClose && !this.destroyed) {
      this.scheduleReconnect();
    }
  }

  // ─── Helpers ────────────────────────────────────────────

  /**
   * Clear all pending timers (heartbeat + reconnect).
   */
  private clearTimers(): void {
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }
}

// ─── SimplePeerConnectionPool ─────────────────────────────────

/**
 * Manages a pool of {@link SimplePeerConnection} instances.
 *
 * Ensures at most one connection per peer name, provides lookup by name,
 * and handles bulk connect/disconnect operations.
 */
export class SimplePeerConnectionPool extends EventEmitter {
  /** Active connections keyed by peer name. */
  private readonly connections = new Map<string, SimplePeerConnection>();

  /**
   * Get a connection by peer name.
   *
   * @param name - The peer's display name.
   * @returns The connection instance, or `undefined` if not found.
   */
  get(name: string): SimplePeerConnection | undefined {
    return this.connections.get(name);
  }

  /**
   * Check if a peer is connected and ready.
   *
   * @param name - The peer's display name.
   */
  isConnected(name: string): boolean {
    return this.connections.get(name)?.status === "connected";
  }

  /**
   * Get all connections.
   */
  getAll(): ReadonlyMap<string, SimplePeerConnection> {
    return this.connections;
  }

  /**
   * Get status info for all peers in the pool.
   */
  getStatusAll(): Array<{
    name: string;
    endpoint: string;
    status: SimplePeerStatus;
    latencyMs: number | null;
  }> {
    const result: Array<{
      name: string;
      endpoint: string;
      status: SimplePeerStatus;
      latencyMs: number | null;
    }> = [];

    for (const [name, conn] of this.connections) {
      result.push({
        name,
        endpoint: conn.endpoint,
        status: conn.status,
        latencyMs: conn.latencyMs,
      });
    }

    return result;
  }

  /**
   * Add and connect to a peer. If a connection with the same name already
   * exists, it is disconnected first.
   *
   * @param params - Peer connection parameters.
   * @returns The created {@link SimplePeerConnection}.
   */
  async add(params: {
    peerName: string;
    endpoint: string;
    token: string;
  }): Promise<SimplePeerConnection> {
    // Remove existing connection with same name.
    const existing = this.connections.get(params.peerName);
    if (existing) {
      await existing.destroy();
      this.connections.delete(params.peerName);
    }

    const conn = new SimplePeerConnection(params);

    // Forward events.
    conn.on("connected", () => {
      this.emit("peer.connected", { name: params.peerName });
    });
    conn.on("disconnected", (code: number, reason: string) => {
      this.emit("peer.disconnected", { name: params.peerName, code, reason });
    });
    conn.on("reconnecting", (attempt: number, delayMs: number) => {
      this.emit("peer.reconnecting", { name: params.peerName, attempt, delayMs });
    });
    conn.on("message", (data: unknown) => {
      this.emit("peer.message", { name: params.peerName, data });
    });

    this.connections.set(params.peerName, conn);

    // Attempt connection (non-blocking — reconnect handles failures).
    try {
      await conn.connect();
    } catch (err) {
      log("warn", `Initial connection to simple peer "${params.peerName}" failed`, {
        error: String(err),
      });
      // Reconnect is already scheduled by the connection itself.
    }

    return conn;
  }

  /**
   * Remove a peer from the pool and disconnect.
   *
   * @param name - The peer's display name.
   */
  async remove(name: string): Promise<void> {
    const conn = this.connections.get(name);
    if (conn) {
      await conn.destroy();
      this.connections.delete(name);
    }
  }

  /**
   * Disconnect and destroy all connections in the pool.
   */
  async shutdown(): Promise<void> {
    const promises: Promise<void>[] = [];
    for (const [_name, conn] of this.connections) {
      promises.push(conn.destroy());
    }
    await Promise.allSettled(promises);
    this.connections.clear();
    this.emit("shutdown");
  }
}
