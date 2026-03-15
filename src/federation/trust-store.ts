/**
 * Federation Trust Store — Persistent peer trust management
 *
 * Stores known peers, their public keys, trust levels, and capability grants.
 * File-based storage with 0o600 permissions (like device identity).
 */

import fs from "node:fs";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";
import {
  derivePeerIdFromPublicKey,
  verifyCapabilityGrant,
  isCapabilityGrantExpired,
} from "./crypto.js";
import type {
  CapabilityGrant,
  FederationCapability,
  FederationIdentity,
  PeerEndpoint,
  TrustLevel,
  TrustedPeer,
} from "./types.js";

// ─── Store ──────────────────────────────────────────────────

type StoredTrustStore = {
  version: 1;
  peers: Record<string, StoredPeer>;
  updatedAt: number;
};

type StoredPeer = {
  identity: FederationIdentity;
  trust: TrustLevel;
  vouchedBy?: string;
  endpoint: PeerEndpoint;
  grantedCapabilities: CapabilityGrant;
  receivedCapabilities?: CapabilityGrant;
  addedAt: number;
  lastSeenAt?: number;
};

function resolveTrustStorePath(): string {
  return path.join(resolveStateDir(), "federation", "trust-store.json");
}

export class TrustStore {
  private peers: Map<string, TrustedPeer> = new Map();
  private readonly storePath: string;

  constructor(storePathOrOpts?: string | { stateDir?: string; storePath?: string }) {
    if (typeof storePathOrOpts === "object" && storePathOrOpts !== null) {
      this.storePath =
        storePathOrOpts.storePath ??
        (storePathOrOpts.stateDir
          ? path.join(storePathOrOpts.stateDir, "federation", "trust-store.json")
          : resolveTrustStorePath());
    } else {
      this.storePath = storePathOrOpts ?? resolveTrustStorePath();
    }
    this.load();
  }

  // ─── Persistence ────────────────────────────────────────

  private load(): void {
    try {
      if (!fs.existsSync(this.storePath)) {
        return;
      }
      const raw = fs.readFileSync(this.storePath, "utf8");
      const stored = JSON.parse(raw) as StoredTrustStore;
      if (stored?.version !== 1) {
        return;
      }

      for (const [peerId, peer] of Object.entries(stored.peers)) {
        this.peers.set(peerId, { ...peer, connected: false });
      }
    } catch {
      // Start with empty store
    }
  }

  private save(): void {
    const stored: StoredTrustStore = {
      version: 1,
      peers: Object.fromEntries(
        Array.from(this.peers.entries()).map(([id, peer]) => {
          const { connected: _connected, ...rest } = peer;
          return [id, rest];
        }),
      ),
      updatedAt: Date.now(),
    };

    fs.mkdirSync(path.dirname(this.storePath), { recursive: true });
    fs.writeFileSync(this.storePath, `${JSON.stringify(stored, null, 2)}\n`, { mode: 0o600 });
    try {
      fs.chmodSync(this.storePath, 0o600);
    } catch {
      // best-effort
    }
  }

  // ─── Peer Management ────────────────────────────────────

  getPeer(peerId: string): TrustedPeer | undefined {
    return this.peers.get(peerId);
  }

  listPeers(): TrustedPeer[] {
    return Array.from(this.peers.values());
  }

  listConnectedPeers(): TrustedPeer[] {
    return this.listPeers().filter((p) => p.connected);
  }

  listTrustedPeers(): TrustedPeer[] {
    return this.listPeers().filter((p) => p.trust === "direct" || p.trust === "vouched");
  }

  /**
   * Add or update a directly-trusted peer.
   */
  addDirectPeer(params: {
    identity: FederationIdentity;
    endpoint: PeerEndpoint;
    grant: CapabilityGrant;
  }): void {
    // Verify peerId matches public key
    const derivedId = derivePeerIdFromPublicKey(params.identity.publicKeyPem);
    if (derivedId !== params.identity.peerId) {
      throw new Error(`Peer ID mismatch: expected ${derivedId}, got ${params.identity.peerId}`);
    }

    this.peers.set(params.identity.peerId, {
      identity: params.identity,
      trust: "direct",
      endpoint: params.endpoint,
      grantedCapabilities: params.grant,
      addedAt: Date.now(),
      connected: false,
    });
    this.save();
  }

  /**
   * Add a vouched peer (introduced by a trusted peer).
   */
  addVouchedPeer(params: {
    identity: FederationIdentity;
    endpoint: PeerEndpoint;
    vouchedBy: string;
    grant: CapabilityGrant;
  }): boolean {
    // Only accept introductions from directly trusted peers
    const voucher = this.peers.get(params.vouchedBy);
    if (!voucher || voucher.trust !== "direct") {
      return false;
    }

    // Don't override direct trust with vouched
    const existing = this.peers.get(params.identity.peerId);
    if (existing?.trust === "direct") {
      return false;
    }

    this.peers.set(params.identity.peerId, {
      identity: params.identity,
      trust: "vouched",
      vouchedBy: params.vouchedBy,
      endpoint: params.endpoint,
      grantedCapabilities: params.grant,
      addedAt: Date.now(),
      connected: false,
    });
    this.save();
    return true;
  }

  /**
   * Remove a peer from the trust store.
   */
  removePeer(peerId: string): boolean {
    const deleted = this.peers.delete(peerId);
    if (deleted) {
      this.save();
    }
    return deleted;
  }

  /**
   * Update peer connection state (not persisted — runtime only).
   */
  setConnected(peerId: string, connected: boolean): void {
    const peer = this.peers.get(peerId);
    if (peer) {
      peer.connected = connected;
      if (connected) {
        peer.lastSeenAt = Date.now();
      }
    }
  }

  /**
   * Store a capability grant received from a peer.
   */
  setReceivedCapabilities(peerId: string, grant: CapabilityGrant): void {
    const peer = this.peers.get(peerId);
    if (!peer) {
      return;
    }

    // Verify the grant is signed by the peer
    if (!verifyCapabilityGrant(peer.identity.publicKeyPem, grant)) {
      throw new Error(`Invalid capability grant signature from peer ${peerId}`);
    }

    peer.receivedCapabilities = grant;
    this.save();
  }

  // ─── Authorization ──────────────────────────────────────

  /**
   * Check if a peer has a specific capability (that we granted).
   */
  peerHasCapability(peerId: string, capability: FederationCapability): boolean {
    const peer = this.peers.get(peerId);
    if (!peer) {
      return false;
    }
    if (peer.trust === "unknown") {
      return false;
    }

    const grant = peer.grantedCapabilities;
    if (isCapabilityGrantExpired(grant)) {
      return false;
    }
    return grant.capabilities.includes(capability);
  }

  /**
   * Check if we have a specific capability on a peer (that they granted to us).
   */
  weHaveCapabilityOn(peerId: string, capability: FederationCapability): boolean {
    const peer = this.peers.get(peerId);
    if (!peer?.receivedCapabilities) {
      return false;
    }
    if (isCapabilityGrantExpired(peer.receivedCapabilities)) {
      return false;
    }
    return peer.receivedCapabilities.capabilities.includes(capability);
  }

  /**
   * Check rate limit for a peer.
   * Returns true if the request should be allowed.
   */
  private readonly rateCounts = new Map<
    string,
    { minute: number; hour: number; day: number; lastReset: number }
  >();

  checkRateLimit(peerId: string): boolean {
    const peer = this.peers.get(peerId);
    if (!peer) {
      return false;
    }

    const limit = peer.grantedCapabilities.rateLimit;
    if (!limit) {
      return true;
    } // No limit configured

    const now = Date.now();
    let counts = this.rateCounts.get(peerId);
    if (!counts || now - counts.lastReset > 86400000) {
      counts = { minute: 0, hour: 0, day: 0, lastReset: now };
      this.rateCounts.set(peerId, counts);
    }

    // Simple sliding window (approximate)
    counts.minute++;
    counts.hour++;
    counts.day++;

    if (limit.maxMessagesPerMinute && counts.minute > limit.maxMessagesPerMinute) {
      return false;
    }
    if (limit.maxMessagesPerHour && counts.hour > limit.maxMessagesPerHour) {
      return false;
    }
    if (limit.maxMessagesPerDay && counts.day > limit.maxMessagesPerDay) {
      return false;
    }

    return true;
  }
}
