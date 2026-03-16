/**
 * Federation AutoConnector — Automatic peer connection & online status management
 *
 * Orchestrates outbound connections to all trusted peers at startup:
 * - Iterates trust store for peers with `endpoint.wsUrl`
 * - Delegates actual WS connections to {@link FederationTransport}
 * - Periodically rescans trust store for newly added peers
 * - Provides a unified API for querying real-time connection status
 *
 * The heavy lifting (handshake, heartbeat, reconnect with backoff) is
 * handled by the FederationTransport. AutoConnector is the orchestrator
 * that decides **when** and **which** peers to connect to.
 */

import { createSubsystemLogger } from "../logging/subsystem.js";
import type { FederationNode } from "./client.js";
import { formatPeerId } from "./crypto.js";
import type { FederationTransport } from "./transport.js";
import type { TrustStore } from "./trust-store.js";

const log = createSubsystemLogger("federation:auto-connector");

// ─── Constants ──────────────────────────────────────────────

/** Default interval for rescanning the trust store for new peers (ms). */
const DEFAULT_RESCAN_INTERVAL_MS = 60_000;

/** Initial delay before the first connection sweep (ms). */
const INITIAL_CONNECT_DELAY_MS = 2_000;

// ─── AutoConnector ──────────────────────────────────────────

export interface AutoConnectorOptions {
  /** The FederationNode instance. */
  node: FederationNode;
  /** The trust store to scan for peers. */
  trustStore: TrustStore;
  /** The transport layer that manages actual WS connections. */
  transport: FederationTransport;
  /**
   * Interval for rescanning the trust store for newly added peers (ms).
   * Default: 60000 (1 minute).
   */
  rescanIntervalMs?: number;
}

export class AutoConnector {
  private readonly node: FederationNode;
  private readonly trustStore: TrustStore;
  private readonly transport: FederationTransport;
  private readonly rescanIntervalMs: number;

  /** Timer for the periodic trust store rescan. */
  private rescanTimer: ReturnType<typeof setInterval> | null = null;

  /** Timer for the initial delayed connect. */
  private initialConnectTimer: ReturnType<typeof setTimeout> | null = null;

  /** Set of peer IDs we've already attempted to connect to. */
  private readonly knownPeerIds = new Set<string>();

  /** Whether the AutoConnector has been started. */
  private running = false;

  /** Whether the AutoConnector has been shut down. */
  private destroyed = false;

  constructor(opts: AutoConnectorOptions) {
    this.node = opts.node;
    this.trustStore = opts.trustStore;
    this.transport = opts.transport;
    this.rescanIntervalMs = opts.rescanIntervalMs ?? DEFAULT_RESCAN_INTERVAL_MS;
  }

  // ─── Lifecycle ──────────────────────────────────────────

  /**
   * Start the AutoConnector.
   *
   * Connects to all trusted peers with endpoints after a brief delay
   * (to allow the Gateway HTTP server to finish binding), then sets up
   * periodic rescanning for newly added peers.
   */
  start(): void {
    if (this.running || this.destroyed) {
      return;
    }
    this.running = true;

    log.info("auto-connector starting");

    // Delay initial connection sweep to let the Gateway finish startup.
    this.initialConnectTimer = setTimeout(() => {
      this.initialConnectTimer = null;
      this.connectAllPeers();
    }, INITIAL_CONNECT_DELAY_MS);

    // Periodically rescan for new peers added via pairing or RPC.
    this.rescanTimer = setInterval(() => {
      this.rescanForNewPeers();
    }, this.rescanIntervalMs);

    log.info(
      `auto-connector started: initial connect in ${INITIAL_CONNECT_DELAY_MS}ms, ` +
        `rescan every ${this.rescanIntervalMs}ms`,
    );
  }

  /**
   * Stop the AutoConnector and clean up all timers.
   *
   * Note: this does NOT disconnect existing peer connections — those are
   * managed by the FederationTransport's shutdown().
   */
  shutdown(): void {
    if (this.destroyed) {
      return;
    }
    this.destroyed = true;
    this.running = false;

    if (this.initialConnectTimer) {
      clearTimeout(this.initialConnectTimer);
      this.initialConnectTimer = null;
    }

    if (this.rescanTimer) {
      clearInterval(this.rescanTimer);
      this.rescanTimer = null;
    }

    this.knownPeerIds.clear();

    log.info("auto-connector shut down");
  }

  // ─── Connection ─────────────────────────────────────────

  /**
   * Connect to all trusted peers that have a `wsUrl` endpoint.
   * This is the initial sweep called at startup.
   */
  private connectAllPeers(): void {
    if (this.destroyed) {
      return;
    }

    // Reload trust store from disk in case peers were added externally
    this.trustStore.reload();

    const peers = this.trustStore.listPeers();
    let attempted = 0;

    for (const peer of peers) {
      if (peer.endpoint.wsUrl) {
        this.knownPeerIds.add(peer.identity.peerId);
        attempted++;
      }
    }

    // Delegate the actual connections to the transport.
    // The transport handles dedup, handshakes, and backoff internally.
    this.transport.connectToAllPeers();

    log.info(
      `auto-connector initial sweep: ${attempted} peers with endpoints ` +
        `(of ${peers.length} total trusted)`,
    );
  }

  /**
   * Rescan the trust store for peers that were added since the last scan
   * (e.g. via pairing or RPC). Connect to any new peers with endpoints.
   */
  private rescanForNewPeers(): void {
    if (this.destroyed) {
      return;
    }

    // Reload trust store from disk to pick up peers added by CLI pairing
    this.trustStore.reload();

    const peers = this.trustStore.listPeers();
    let newPeers = 0;

    for (const peer of peers) {
      if (peer.endpoint.wsUrl && !this.knownPeerIds.has(peer.identity.peerId)) {
        this.knownPeerIds.add(peer.identity.peerId);
        newPeers++;

        log.info(
          `auto-connector: new peer discovered — ${peer.identity.name} ` +
            `(${formatPeerId(peer.identity.peerId)}), connecting...`,
        );

        this.transport.connectToPeer(peer.endpoint);
      }
    }

    // Also clean up knownPeerIds for removed peers
    for (const id of this.knownPeerIds) {
      if (!peers.some((p) => p.identity.peerId === id)) {
        this.knownPeerIds.delete(id);
      }
    }

    if (newPeers > 0) {
      log.info(`auto-connector rescan: connected to ${newPeers} new peer(s)`);
    }
  }

  // ─── Status Queries ─────────────────────────────────────

  /**
   * Check if a specific peer is currently connected (handshake complete).
   */
  isConnected(peerId: string): boolean {
    return this.transport.isPeerConnected(peerId);
  }

  /**
   * Get the peer IDs of all currently connected peers.
   */
  getConnectedPeers(): string[] {
    return this.transport
      .getConnectionInfo()
      .filter((c) => c.phase === "Ready")
      .map((c) => c.peerId);
  }

  /**
   * Get detailed connection status for all peers.
   * Merges trust store info with live transport connection state.
   */
  getDetailedStatus(): Array<{
    peerId: string;
    peerName: string;
    connected: boolean;
    trust: string;
    endpoint?: string;
    capabilities: string[];
    lastSeenAt?: number;
    connectionPhase?: string;
    connectionDirection?: string;
    connectedAt?: number;
  }> {
    const peers = this.trustStore.listPeers();
    const connectionInfo = this.transport.getConnectionInfo();
    const connectionMap = new Map(connectionInfo.map((c) => [c.peerId, c]));

    return peers.map((peer) => {
      const conn = connectionMap.get(peer.identity.peerId);
      const isConnected = conn?.phase === "Ready";

      return {
        peerId: peer.identity.peerId,
        peerName: peer.identity.name,
        connected: isConnected,
        trust: peer.trust,
        endpoint: peer.endpoint.wsUrl ?? peer.endpoint.httpUrl,
        capabilities: peer.grantedCapabilities.capabilities,
        lastSeenAt: peer.lastSeenAt,
        connectionPhase: conn?.phase,
        connectionDirection: conn?.outbound ? "outbound" : conn ? "inbound" : undefined,
        connectedAt: conn?.connectedAt,
      };
    });
  }
}
