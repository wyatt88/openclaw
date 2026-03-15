/**
 * Federation Module — Comprehensive Unit Tests
 *
 * Covers:
 * - Crypto: key generation, signing, verification, challenge-response, capability grants
 * - Trust Store: peer management, trust levels, capabilities, rate limiting, persistence
 * - FederationNode: handshake flow, chat messages, authorization, expiry
 * - Audit Log: event logging, ring buffer, rotation, export
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FederationAuditLog } from "./audit.js";
import { FederationNode } from "./client.js";
import {
  loadOrCreateFederationIdentity,
  signPayload,
  verifySignature,
  generateChallenge,
  createSignedMessage,
  verifySignedMessage,
  createCapabilityGrant,
  verifyCapabilityGrant,
  isCapabilityGrantExpired,
  hasCapability,
  formatPeerId,
  derivePeerIdFromPublicKey,
} from "./crypto.js";
import { TrustStore } from "./trust-store.js";
import type { FederationLocalIdentity, CapabilityGrant, FederationCapability } from "./types.js";

// ─── Test Helpers ───────────────────────────────────────────

function makeTmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "fed-test-"));
}

function createTestIdentity(name: string, dir?: string): FederationLocalIdentity {
  const d = dir ?? makeTmpDir();
  return loadOrCreateFederationIdentity(name, path.join(d, `${name}-identity.json`));
}

function createTestGrant(
  grantor: FederationLocalIdentity,
  granteeId: string,
  capabilities: FederationCapability[] = ["chat"],
  options?: { rateLimit?: CapabilityGrant["rateLimit"]; expiresAt?: number },
): CapabilityGrant {
  return createCapabilityGrant(grantor, {
    grantee: granteeId,
    capabilities,
    rateLimit: options?.rateLimit,
    expiresAt: options?.expiresAt,
  });
}

// ─── Crypto Tests ───────────────────────────────────────────

describe("Federation Crypto", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe("Key Generation", () => {
    it("should generate a valid Ed25519 identity", () => {
      const identity = createTestIdentity("test-node", tmpDir);

      expect(identity.peerId).toMatch(/^[0-9a-f]{64}$/);
      expect(identity.name).toBe("test-node");
      expect(identity.publicKeyPem).toContain("BEGIN PUBLIC KEY");
      expect(identity.privateKeyPem).toContain("BEGIN PRIVATE KEY");
    });

    it("should load an existing identity from disk", () => {
      const filePath = path.join(tmpDir, "id.json");
      const first = loadOrCreateFederationIdentity("node-a", filePath);
      const second = loadOrCreateFederationIdentity("node-a", filePath);

      expect(second.peerId).toBe(first.peerId);
      expect(second.publicKeyPem).toBe(first.publicKeyPem);
      expect(second.privateKeyPem).toBe(first.privateKeyPem);
    });

    it("should derive consistent peerId from public key", () => {
      const identity = createTestIdentity("test", tmpDir);
      const derived = derivePeerIdFromPublicKey(identity.publicKeyPem);

      expect(derived).toBe(identity.peerId);
    });

    it("should generate unique identities", () => {
      const a = createTestIdentity("a", tmpDir);
      const b = createTestIdentity("b", tmpDir);

      expect(a.peerId).not.toBe(b.peerId);
      expect(a.publicKeyPem).not.toBe(b.publicKeyPem);
    });
  });

  describe("Signing & Verification", () => {
    it("should sign and verify a payload", () => {
      const identity = createTestIdentity("signer", tmpDir);
      const payload = "hello federation";
      const sig = signPayload(identity.privateKeyPem, payload);

      expect(sig).toBeTruthy();
      expect(typeof sig).toBe("string");

      const valid = verifySignature(identity.publicKeyPem, payload, sig);
      expect(valid).toBe(true);
    });

    it("should reject an incorrect signature", () => {
      const a = createTestIdentity("a", tmpDir);
      const b = createTestIdentity("b", tmpDir);

      const payload = "secret message";
      const sig = signPayload(a.privateKeyPem, payload);

      // Verify with wrong key
      const valid = verifySignature(b.publicKeyPem, payload, sig);
      expect(valid).toBe(false);
    });

    it("should reject a tampered payload", () => {
      const identity = createTestIdentity("signer", tmpDir);
      const sig = signPayload(identity.privateKeyPem, "original");

      const valid = verifySignature(identity.publicKeyPem, "tampered", sig);
      expect(valid).toBe(false);
    });

    it("should reject a corrupted signature", () => {
      const identity = createTestIdentity("signer", tmpDir);
      const sig = signPayload(identity.privateKeyPem, "data");

      // Corrupt the signature
      const corrupted = sig.slice(0, -4) + "XXXX";
      const valid = verifySignature(identity.publicKeyPem, "data", corrupted);
      expect(valid).toBe(false);
    });
  });

  describe("Challenge-Response", () => {
    it("should generate a 64-char hex challenge", () => {
      const challenge = generateChallenge();
      expect(challenge).toMatch(/^[0-9a-f]{64}$/);
    });

    it("should complete a full challenge-response flow", () => {
      const alice = createTestIdentity("alice", tmpDir);
      const bob = createTestIdentity("bob", tmpDir);

      // Alice sends challenge
      const challenge = generateChallenge();

      // Bob signs the challenge
      const response = signPayload(bob.privateKeyPem, challenge);

      // Alice verifies Bob's response
      const valid = verifySignature(bob.publicKeyPem, challenge, response);
      expect(valid).toBe(true);

      // Bob sends counter-challenge
      const counterChallenge = generateChallenge();

      // Alice signs counter-challenge
      const counterResponse = signPayload(alice.privateKeyPem, counterChallenge);

      // Bob verifies Alice's response
      const counterValid = verifySignature(alice.publicKeyPem, counterChallenge, counterResponse);
      expect(counterValid).toBe(true);
    });

    it("should reject challenge signed by wrong key", () => {
      const alice = createTestIdentity("alice", tmpDir);
      const eve = createTestIdentity("eve", tmpDir);

      const challenge = generateChallenge();
      const eveResponse = signPayload(eve.privateKeyPem, challenge);

      // Verify using alice's key (should fail — eve signed it)
      const valid = verifySignature(alice.publicKeyPem, challenge, eveResponse);
      expect(valid).toBe(false);
    });
  });

  describe("Signed Messages", () => {
    it("should create and verify a signed message", () => {
      const identity = createTestIdentity("sender", tmpDir);
      const msg = createSignedMessage(identity, { type: "ping", data: {} });

      expect(msg.senderId).toBe(identity.peerId);
      expect(msg.signature).toBeTruthy();
      expect(msg.seq).toBeGreaterThan(0);
      expect(msg.timestamp).toBeGreaterThan(0);

      const result = verifySignedMessage(identity.publicKeyPem, msg);
      expect(result.valid).toBe(true);
      expect(result.payload).toEqual({ type: "ping", data: {} });
    });

    it("should reject a message with wrong public key", () => {
      const sender = createTestIdentity("sender", tmpDir);
      const other = createTestIdentity("other", tmpDir);
      const msg = createSignedMessage(sender, { type: "ping", data: {} });

      const result = verifySignedMessage(other.publicKeyPem, msg);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("Invalid signature");
    });

    it("should reject an expired message (>5 minutes)", () => {
      const identity = createTestIdentity("sender", tmpDir);
      const msg = createSignedMessage(identity, { type: "ping", data: {} });

      // Forge timestamp to be 6 minutes ago
      msg.timestamp = Date.now() - 6 * 60 * 1000;
      // Re-sign with correct timestamp in signData
      const signData = `${msg.payload}|${msg.seq}|${msg.timestamp}`;
      msg.signature = signPayload(identity.privateKeyPem, signData);

      const result = verifySignedMessage(identity.publicKeyPem, msg);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("expired");
    });

    it("should reject a message from the future (>1 minute)", () => {
      const identity = createTestIdentity("sender", tmpDir);
      const msg = createSignedMessage(identity, { type: "ping", data: {} });

      // Forge timestamp 2 minutes in the future
      msg.timestamp = Date.now() + 2 * 60 * 1000;
      const signData = `${msg.payload}|${msg.seq}|${msg.timestamp}`;
      msg.signature = signPayload(identity.privateKeyPem, signData);

      const result = verifySignedMessage(identity.publicKeyPem, msg);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("future");
    });
  });

  describe("Capability Grants", () => {
    it("should create and verify a capability grant", () => {
      const grantor = createTestIdentity("grantor", tmpDir);
      const granteeId = "abc123";

      const grant = createTestGrant(grantor, granteeId, ["chat", "weather"]);

      expect(grant.grantor).toBe(grantor.peerId);
      expect(grant.grantee).toBe(granteeId);
      expect(grant.capabilities).toEqual(["chat", "weather"]);
      expect(grant.signature).toBeTruthy();
      expect(grant.issuedAt).toBeGreaterThan(0);

      const valid = verifyCapabilityGrant(grantor.publicKeyPem, grant);
      expect(valid).toBe(true);
    });

    it("should reject a tampered grant", () => {
      const grantor = createTestIdentity("grantor", tmpDir);
      const grant = createTestGrant(grantor, "grantee1", ["chat"]);

      // Tamper with capabilities
      grant.capabilities = ["chat", "calendar.write"];

      const valid = verifyCapabilityGrant(grantor.publicKeyPem, grant);
      expect(valid).toBe(false);
    });

    it("should detect expired grants", () => {
      const grantor = createTestIdentity("grantor", tmpDir);
      const grant = createTestGrant(grantor, "grantee1", ["chat"], {
        expiresAt: Date.now() - 1000,
      });

      expect(isCapabilityGrantExpired(grant)).toBe(true);
    });

    it("should not expire grants with expiresAt=0", () => {
      const grantor = createTestIdentity("grantor", tmpDir);
      const grant = createTestGrant(grantor, "grantee1", ["chat"], {
        expiresAt: 0,
      });

      expect(isCapabilityGrantExpired(grant)).toBe(false);
    });

    it("should check hasCapability correctly", () => {
      const grantor = createTestIdentity("grantor", tmpDir);
      const grant = createTestGrant(grantor, "grantee1", ["chat", "weather"]);

      expect(hasCapability(grant, "chat")).toBe(true);
      expect(hasCapability(grant, "weather")).toBe(true);
      expect(hasCapability(grant, "calendar.write")).toBe(false);
    });

    it("should deny capability on expired grant", () => {
      const grantor = createTestIdentity("grantor", tmpDir);
      const grant = createTestGrant(grantor, "grantee1", ["chat"], {
        expiresAt: Date.now() - 1000,
      });

      expect(hasCapability(grant, "chat")).toBe(false);
    });

    it("should return false for undefined grant", () => {
      expect(hasCapability(undefined, "chat")).toBe(false);
    });
  });

  describe("Peer ID Formatting", () => {
    it("should format long peer IDs", () => {
      const formatted = formatPeerId(
        "a7f3bc9d1e2f0000000000000000000000000000000000000000000000001e2f",
      );
      expect(formatted).toBe("oc1_a7f3...1e2f");
    });

    it("should handle short peer IDs", () => {
      const formatted = formatPeerId("short");
      expect(formatted).toBe("oc1_short");
    });
  });
});

// ─── Trust Store Tests ──────────────────────────────────────

describe("Trust Store", () => {
  let tmpDir: string;
  let alice: FederationLocalIdentity;
  let bob: FederationLocalIdentity;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    alice = createTestIdentity("alice", tmpDir);
    bob = createTestIdentity("bob", tmpDir);
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function createStore(): TrustStore {
    return new TrustStore(path.join(tmpDir, "trust-store.json"));
  }

  describe("Peer Management", () => {
    it("should add and retrieve a direct peer", () => {
      const store = createStore();
      const grant = createTestGrant(alice, bob.peerId, ["chat"]);

      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: { wsUrl: "wss://bob.example.com" },
        grant,
      });

      const peer = store.getPeer(bob.peerId);
      expect(peer).toBeDefined();
      expect(peer!.identity.name).toBe("bob");
      expect(peer!.trust).toBe("direct");
      expect(peer!.connected).toBe(false);
    });

    it("should list all peers", () => {
      const store = createStore();

      const carol = createTestIdentity("carol", tmpDir);
      const grantBob = createTestGrant(alice, bob.peerId, ["chat"]);
      const grantCarol = createTestGrant(alice, carol.peerId, ["chat"]);

      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: {},
        grant: grantBob,
      });
      store.addDirectPeer({
        identity: { peerId: carol.peerId, publicKeyPem: carol.publicKeyPem, name: "carol" },
        endpoint: {},
        grant: grantCarol,
      });

      expect(store.listPeers()).toHaveLength(2);
      expect(store.listTrustedPeers()).toHaveLength(2);
    });

    it("should remove a peer", () => {
      const store = createStore();
      const grant = createTestGrant(alice, bob.peerId, ["chat"]);

      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: {},
        grant,
      });

      expect(store.removePeer(bob.peerId)).toBe(true);
      expect(store.getPeer(bob.peerId)).toBeUndefined();
      expect(store.removePeer(bob.peerId)).toBe(false); // Already removed
    });

    it("should reject peer with mismatched peerId", () => {
      const store = createStore();
      const grant = createTestGrant(alice, "fake-id", ["chat"]);

      expect(() =>
        store.addDirectPeer({
          identity: { peerId: "fake-id", publicKeyPem: bob.publicKeyPem, name: "bob" },
          endpoint: {},
          grant,
        }),
      ).toThrow("Peer ID mismatch");
    });
  });

  describe("Direct vs Vouched Trust", () => {
    it("should add a vouched peer when voucher is directly trusted", () => {
      const store = createStore();
      const carol = createTestIdentity("carol", tmpDir);

      // First add Bob as directly trusted
      const grantBob = createTestGrant(alice, bob.peerId, ["chat", "introduce"]);
      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: {},
        grant: grantBob,
      });

      // Bob vouches for Carol
      const grantCarol = createTestGrant(alice, carol.peerId, ["chat"]);
      const added = store.addVouchedPeer({
        identity: { peerId: carol.peerId, publicKeyPem: carol.publicKeyPem, name: "carol" },
        endpoint: {},
        vouchedBy: bob.peerId,
        grant: grantCarol,
      });

      expect(added).toBe(true);
      const peer = store.getPeer(carol.peerId);
      expect(peer!.trust).toBe("vouched");
      expect(peer!.vouchedBy).toBe(bob.peerId);
    });

    it("should reject vouched peer when voucher is not directly trusted", () => {
      const store = createStore();
      const carol = createTestIdentity("carol", tmpDir);
      const grantCarol = createTestGrant(alice, carol.peerId, ["chat"]);

      // Bob is not in the store
      const added = store.addVouchedPeer({
        identity: { peerId: carol.peerId, publicKeyPem: carol.publicKeyPem, name: "carol" },
        endpoint: {},
        vouchedBy: bob.peerId,
        grant: grantCarol,
      });

      expect(added).toBe(false);
      expect(store.getPeer(carol.peerId)).toBeUndefined();
    });

    it("should not downgrade direct trust to vouched", () => {
      const store = createStore();
      const carol = createTestIdentity("carol", tmpDir);

      // Add carol as direct
      const grant = createTestGrant(alice, carol.peerId, ["chat"]);
      store.addDirectPeer({
        identity: { peerId: carol.peerId, publicKeyPem: carol.publicKeyPem, name: "carol" },
        endpoint: {},
        grant,
      });

      // Add bob as direct (for vouching)
      const grantBob = createTestGrant(alice, bob.peerId, ["chat"]);
      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: {},
        grant: grantBob,
      });

      // Try to add carol as vouched by bob
      const result = store.addVouchedPeer({
        identity: { peerId: carol.peerId, publicKeyPem: carol.publicKeyPem, name: "carol" },
        endpoint: {},
        vouchedBy: bob.peerId,
        grant,
      });

      expect(result).toBe(false);
      expect(store.getPeer(carol.peerId)!.trust).toBe("direct");
    });
  });

  describe("Capability Checks", () => {
    it("should check granted capabilities", () => {
      const store = createStore();
      const grant = createTestGrant(alice, bob.peerId, ["chat", "weather"]);

      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: {},
        grant,
      });

      expect(store.peerHasCapability(bob.peerId, "chat")).toBe(true);
      expect(store.peerHasCapability(bob.peerId, "weather")).toBe(true);
      expect(store.peerHasCapability(bob.peerId, "calendar.write")).toBe(false);
    });

    it("should reject capability check for unknown peer", () => {
      const store = createStore();
      expect(store.peerHasCapability("nonexistent", "chat")).toBe(false);
    });

    it("should reject expired capabilities", () => {
      const store = createStore();
      const grant = createTestGrant(alice, bob.peerId, ["chat"], {
        expiresAt: Date.now() - 1000,
      });

      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: {},
        grant,
      });

      expect(store.peerHasCapability(bob.peerId, "chat")).toBe(false);
    });
  });

  describe("Rate Limiting", () => {
    it("should allow requests within rate limit", () => {
      const store = createStore();
      const grant = createTestGrant(alice, bob.peerId, ["chat"], {
        rateLimit: { maxMessagesPerMinute: 5 },
      });

      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: {},
        grant,
      });

      for (let i = 0; i < 5; i++) {
        expect(store.checkRateLimit(bob.peerId)).toBe(true);
      }
    });

    it("should block requests exceeding rate limit", () => {
      const store = createStore();
      const grant = createTestGrant(alice, bob.peerId, ["chat"], {
        rateLimit: { maxMessagesPerMinute: 3 },
      });

      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: {},
        grant,
      });

      expect(store.checkRateLimit(bob.peerId)).toBe(true);
      expect(store.checkRateLimit(bob.peerId)).toBe(true);
      expect(store.checkRateLimit(bob.peerId)).toBe(true);
      expect(store.checkRateLimit(bob.peerId)).toBe(false); // Exceeded
    });

    it("should reject rate check for unknown peer", () => {
      const store = createStore();
      expect(store.checkRateLimit("nonexistent")).toBe(false);
    });

    it("should allow unlimited when no rate limit is set", () => {
      const store = createStore();
      const grant = createTestGrant(alice, bob.peerId, ["chat"]);

      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: {},
        grant,
      });

      for (let i = 0; i < 100; i++) {
        expect(store.checkRateLimit(bob.peerId)).toBe(true);
      }
    });
  });

  describe("Persistence", () => {
    it("should persist and reload peers", () => {
      const storePath = path.join(tmpDir, "persist-test.json");
      const grant = createTestGrant(alice, bob.peerId, ["chat", "weather"]);

      // Write
      const store1 = new TrustStore(storePath);
      store1.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: { wsUrl: "wss://bob.example.com" },
        grant,
      });

      // Read (new instance)
      const store2 = new TrustStore(storePath);
      const peer = store2.getPeer(bob.peerId);

      expect(peer).toBeDefined();
      expect(peer!.identity.name).toBe("bob");
      expect(peer!.trust).toBe("direct");
      expect(peer!.endpoint.wsUrl).toBe("wss://bob.example.com");
      expect(peer!.grantedCapabilities.capabilities).toEqual(["chat", "weather"]);
      // connected is runtime-only, should be false after reload
      expect(peer!.connected).toBe(false);
    });

    it("should handle corrupt store file gracefully", () => {
      const storePath = path.join(tmpDir, "corrupt.json");
      fs.writeFileSync(storePath, "NOT VALID JSON{{{");

      const store = new TrustStore(storePath);
      expect(store.listPeers()).toHaveLength(0);
    });
  });

  describe("Connection State", () => {
    it("should track connection state", () => {
      const store = createStore();
      const grant = createTestGrant(alice, bob.peerId, ["chat"]);

      store.addDirectPeer({
        identity: { peerId: bob.peerId, publicKeyPem: bob.publicKeyPem, name: "bob" },
        endpoint: {},
        grant,
      });

      expect(store.listConnectedPeers()).toHaveLength(0);

      store.setConnected(bob.peerId, true);
      expect(store.listConnectedPeers()).toHaveLength(1);
      expect(store.getPeer(bob.peerId)!.lastSeenAt).toBeGreaterThan(0);

      store.setConnected(bob.peerId, false);
      expect(store.listConnectedPeers()).toHaveLength(0);
    });
  });
});

// ─── FederationNode Tests ───────────────────────────────────

describe("FederationNode", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
    // Stub resolveStateDir to use tmp
    vi.stubEnv("OPENCLAW_STATE_DIR", tmpDir);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function createNode(name: string): FederationNode {
    return new FederationNode({
      enabled: true,
      instanceName: name,
    });
  }

  /** Register two nodes as mutual peers with specified capabilities */
  function registerMutualPeers(
    nodeA: FederationNode,
    nodeB: FederationNode,
    caps: FederationCapability[] = ["chat"],
  ): void {
    const grantAtoB = createCapabilityGrant(nodeA.identity, {
      grantee: nodeB.identity.peerId,
      capabilities: caps,
    });
    const grantBtoA = createCapabilityGrant(nodeB.identity, {
      grantee: nodeA.identity.peerId,
      capabilities: caps,
    });

    nodeA.trustStore.addDirectPeer({
      identity: {
        peerId: nodeB.identity.peerId,
        publicKeyPem: nodeB.identity.publicKeyPem,
        name: nodeB.identity.name,
      },
      endpoint: {},
      grant: grantAtoB,
    });

    nodeB.trustStore.addDirectPeer({
      identity: {
        peerId: nodeA.identity.peerId,
        publicKeyPem: nodeA.identity.publicKeyPem,
        name: nodeA.identity.name,
      },
      endpoint: {},
      grant: grantBtoA,
    });
  }

  describe("Full Handshake Flow", () => {
    it("should complete a 4-step handshake between two nodes", () => {
      const ark = createNode("Ark");
      const nova = createNode("Nova");

      // Pre-register as trusted peers
      registerMutualPeers(ark, nova);

      // Step 1: Ark creates Hello
      const hello = ark.createHello();
      expect(hello.senderId).toBe(ark.identity.peerId);

      // Step 2: Nova handles Hello → creates HelloAck
      const ackResult = nova.handleHello(hello);
      expect(ackResult.ok).toBe(true);
      if (!ackResult.ok) {
        return;
      }

      // Step 3: Ark handles HelloAck → creates HelloVerified
      const verifiedResult = ark.handleHelloAck(ackResult.response);
      expect(verifiedResult.ok).toBe(true);
      if (!verifiedResult.ok) {
        return;
      }
      expect(verifiedResult.peerId).toBe(nova.identity.peerId);

      // Step 4: Nova handles HelloVerified
      const finalResult = nova.handleHelloVerified(verifiedResult.response);
      expect(finalResult.ok).toBe(true);

      // Both should now be connected
      expect(ark.trustStore.getPeer(nova.identity.peerId)!.connected).toBe(true);
      expect(nova.trustStore.getPeer(ark.identity.peerId)!.connected).toBe(true);
    });

    it("should emit peer.connected event on handshake completion", () => {
      const ark = createNode("Ark");
      const nova = createNode("Nova");
      registerMutualPeers(ark, nova);

      const events: Array<{ event: string; data: unknown }> = [];
      ark.onEvent((event, data) => events.push({ event, data }));

      const hello = ark.createHello();
      const ackResult = nova.handleHello(hello);
      if (!ackResult.ok) {
        return;
      }
      ark.handleHelloAck(ackResult.response);

      expect(events.some((e) => e.event === "peer.connected")).toBe(true);
    });
  });

  describe("Hello Rejection", () => {
    it("should reject hello from unknown peer", () => {
      const ark = createNode("Ark");
      const stranger = createNode("Stranger");

      // Stranger is NOT registered in Ark's trust store
      const hello = stranger.createHello();
      const result = ark.handleHello(hello);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain("Unknown peer");
      }
    });

    it("should reject hello with invalid signature", () => {
      const ark = createNode("Ark");
      const nova = createNode("Nova");
      registerMutualPeers(ark, nova);

      const hello = ark.createHello();
      // Corrupt signature
      hello.signature = "AAAA" + hello.signature.slice(4);

      const result = nova.handleHello(hello);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain("Invalid signature");
      }
    });
  });

  describe("Chat Messages", () => {
    function setupConnectedPeers() {
      const ark = createNode("Ark");
      const nova = createNode("Nova");
      registerMutualPeers(ark, nova);

      // Complete handshake
      const hello = ark.createHello();
      const ackResult = nova.handleHello(hello);
      if (!ackResult.ok) {
        throw new Error("Handshake step 2 failed");
      }
      const verifiedResult = ark.handleHelloAck(ackResult.response);
      if (!verifiedResult.ok) {
        throw new Error("Handshake step 3 failed");
      }
      nova.handleHelloVerified(verifiedResult.response);

      // After handshake, Nova's handleHelloVerified stores the capability grant
      // from Ark, but Ark doesn't receive one from Nova. We must also give Ark
      // received capabilities from Nova so Ark can call weHaveCapabilityOn().
      const novaGrantToArk = createCapabilityGrant(nova.identity, {
        grantee: ark.identity.peerId,
        capabilities: ["chat"],
      });
      ark.trustStore.setReceivedCapabilities(nova.identity.peerId, novaGrantToArk);

      return { ark, nova };
    }

    it("should create a valid chat message", () => {
      const { ark, nova } = setupConnectedPeers();

      const result = ark.createChatMessage({
        peerId: nova.identity.peerId,
        text: "Hello Nova!",
      });

      expect(result.ok).toBe(true);
      if (!result.ok) {
        return;
      }
      expect(result.message.senderId).toBe(ark.identity.peerId);
      expect(result.conversationId).toBeTruthy();
    });

    it("should handle incoming chat message and produce response", async () => {
      const { ark, nova } = setupConnectedPeers();

      nova.onChat(async ({ text }) => `Echo: ${text}`);

      const chatResult = ark.createChatMessage({
        peerId: nova.identity.peerId,
        text: "Hey there!",
      });
      if (!chatResult.ok) {
        throw new Error("Create chat failed");
      }

      const response = await nova.handleChatMessage(chatResult.message);
      expect(response.ok).toBe(true);
      if (!response.ok) {
        return;
      }

      // Verify the response message is properly signed
      const verified = verifySignedMessage(nova.identity.publicKeyPem, response.response);
      expect(verified.valid).toBe(true);
      const payload = verified.payload as unknown as {
        type: string;
        data: { conversationId: string; text: string; deferredToOwner: boolean };
      };
      expect(payload.type).toBe("chat.response");
      expect(payload.data.text).toBe("Echo: Hey there!");
    });

    it("should reject chat from unknown peer", async () => {
      const ark = createNode("Ark");
      const stranger = createNode("Stranger");

      // Stranger creates a message but is not in Ark's trust store
      const msg = createSignedMessage(stranger.identity, {
        type: "chat",
        data: { conversationId: "conv-1", text: "Hi!" },
      });

      const result = await ark.handleChatMessage(msg);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain("Unknown peer");
      }
    });

    it("should reject chat from peer without chat capability", async () => {
      const ark = createNode("Ark");
      const nova = createNode("Nova");

      // Register nova but grant only 'weather', not 'chat'
      const grant = createCapabilityGrant(ark.identity, {
        grantee: nova.identity.peerId,
        capabilities: ["weather"],
      });
      ark.trustStore.addDirectPeer({
        identity: {
          peerId: nova.identity.peerId,
          publicKeyPem: nova.identity.publicKeyPem,
          name: "Nova",
        },
        endpoint: {},
        grant,
      });

      // Manually set connected to simulate post-handshake
      ark.trustStore.setConnected(nova.identity.peerId, true);

      const msg = createSignedMessage(nova.identity, {
        type: "chat",
        data: { conversationId: "conv-1", text: "Hi!" },
      });

      const result = await ark.handleChatMessage(msg);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain("chat capability");
      }
    });

    it("should reject chat when peer is not connected", () => {
      const ark = createNode("Ark");
      const nova = createNode("Nova");
      registerMutualPeers(ark, nova);

      // Don't complete handshake — peer not connected
      // But we need received capabilities to be set
      const recvGrant = createCapabilityGrant(nova.identity, {
        grantee: ark.identity.peerId,
        capabilities: ["chat"],
      });
      ark.trustStore.setReceivedCapabilities(nova.identity.peerId, recvGrant);

      const result = ark.createChatMessage({
        peerId: nova.identity.peerId,
        text: "Hello?",
      });

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error).toContain("not connected");
      }
    });
  });

  describe("Status", () => {
    it("should report federation status", () => {
      const ark = createNode("Ark");
      const status = ark.getStatus();

      expect(status.enabled).toBe(true);
      expect(status.identity.name).toBe("Ark");
      expect(status.peers).toHaveLength(0);
      expect(status.totalConnected).toBe(0);
    });
  });

  describe("Disconnect", () => {
    it("should disconnect a peer", () => {
      const ark = createNode("Ark");
      const nova = createNode("Nova");
      registerMutualPeers(ark, nova);
      ark.trustStore.setConnected(nova.identity.peerId, true);

      ark.disconnectPeer(nova.identity.peerId);
      expect(ark.trustStore.getPeer(nova.identity.peerId)!.connected).toBe(false);
    });
  });
});

// ─── Audit Log Tests ────────────────────────────────────────

describe("FederationAuditLog", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = makeTmpDir();
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function createAuditLog(ringCapacity = 100): FederationAuditLog {
    return new FederationAuditLog({ stateDir: tmpDir, ringCapacity });
  }

  describe("Event Logging", () => {
    it("should log handshake events", () => {
      const log = createAuditLog();
      log.logHandshake("peer-1", "Alice", true);
      log.logHandshake("peer-2", "Bob", false, "Signature verification failed");

      const recent = log.getRecentLogs(10);
      expect(recent).toHaveLength(2);

      // Newest first
      expect(recent[0].eventType).toBe("handshake");
      expect(recent[0].details.success).toBe(false);
      expect(recent[0].details.error).toBe("Signature verification failed");

      expect(recent[1].eventType).toBe("handshake");
      expect(recent[1].peerName).toBe("Alice");
      expect(recent[1].details.success).toBe(true);

      log.close();
    });

    it("should log message events with direction", () => {
      const log = createAuditLog();
      log.logMessage("outbound", "peer-1", "Alice", "chat", "conv-123", "sig-abc");

      const recent = log.getRecentLogs(1);
      expect(recent[0].eventType).toBe("message");
      expect(recent[0].direction).toBe("outbound");
      expect(recent[0].details.messageType).toBe("chat");
      expect(recent[0].details.conversationId).toBe("conv-123");
      expect(recent[0].messageSignature).toBe("sig-abc");

      log.close();
    });

    it("should log capability change events", () => {
      const log = createAuditLog();
      log.logCapabilityChange("peer-1", "grant", ["chat", "weather"]);

      const recent = log.getRecentLogs(1);
      expect(recent[0].eventType).toBe("capability_change");
      expect(recent[0].details.action).toBe("grant");
      expect(recent[0].details.capabilities).toEqual(["chat", "weather"]);

      log.close();
    });

    it("should log pairing events", () => {
      const log = createAuditLog();
      log.logPairingEvent("peer-1", "Alice", "initiated");
      log.logPairingEvent("peer-1", "Alice", "accepted");

      const recent = log.getRecentLogs(10);
      expect(recent).toHaveLength(2);
      expect(recent[0].details.action).toBe("accepted");
      expect(recent[1].details.action).toBe("initiated");

      log.close();
    });

    it("should log security events", () => {
      const log = createAuditLog();
      log.logSecurityEvent("peer-x", "invalid_signature", {
        messageType: "chat",
        attemptedAt: Date.now(),
      });

      const recent = log.getRecentLogs(1);
      expect(recent[0].eventType).toBe("security");
      expect(recent[0].details.event).toBe("invalid_signature");
      expect(recent[0].details.messageType).toBe("chat");

      log.close();
    });
  });

  describe("JSONL File Storage", () => {
    it("should write entries to JSONL file", () => {
      const log = createAuditLog();
      log.logHandshake("peer-1", "Alice", true);
      log.logMessage("inbound", "peer-1", "Alice", "chat");

      const content = fs.readFileSync(log.activeFilePath, "utf8");
      const lines = content.trim().split("\n");
      expect(lines).toHaveLength(2);

      const entry1 = JSON.parse(lines[0]);
      expect(entry1.eventType).toBe("handshake");

      const entry2 = JSON.parse(lines[1]);
      expect(entry2.eventType).toBe("message");

      log.close();
    });

    it("should include all required fields in each entry", () => {
      const log = createAuditLog();
      log.logHandshake("peer-1", "Alice", true);

      const content = fs.readFileSync(log.activeFilePath, "utf8");
      const entry = JSON.parse(content.trim());

      expect(entry.timestamp).toMatch(/\d{4}-\d{2}-\d{2}T/);
      expect(entry.timestampMs).toBeGreaterThan(0);
      expect(entry.eventType).toBe("handshake");
      expect(entry.peerId).toBe("peer-1");
      expect(entry.peerName).toBe("Alice");
      expect(entry.details).toBeDefined();

      log.close();
    });
  });

  describe("Ring Buffer (Recent Logs)", () => {
    it("should respect the limit parameter", () => {
      const log = createAuditLog();
      for (let i = 0; i < 20; i++) {
        log.logHandshake(`peer-${i}`, `Node-${i}`, true);
      }

      expect(log.getRecentLogs(5)).toHaveLength(5);
      expect(log.getRecentLogs(50)).toHaveLength(20);
      expect(log.getRecentLogs()).toHaveLength(20); // Default 50

      log.close();
    });

    it("should return newest entries first", () => {
      const log = createAuditLog();
      log.logHandshake("peer-1", "First", true);
      log.logHandshake("peer-2", "Second", true);
      log.logHandshake("peer-3", "Third", true);

      const recent = log.getRecentLogs(3);
      expect(recent[0].peerName).toBe("Third");
      expect(recent[1].peerName).toBe("Second");
      expect(recent[2].peerName).toBe("First");

      log.close();
    });

    it("should handle ring buffer overflow", () => {
      const log = createAuditLog(5); // Small capacity
      for (let i = 0; i < 10; i++) {
        log.logHandshake(`peer-${i}`, `Node-${i}`, true);
      }

      // Only last 5 should be in ring
      const recent = log.getRecentLogs(10);
      expect(recent).toHaveLength(5);
      expect(recent[0].peerName).toBe("Node-9");
      expect(recent[4].peerName).toBe("Node-5");

      log.close();
    });
  });

  describe("File Rotation", () => {
    it("should rotate when file exceeds 10MB", () => {
      const log = createAuditLog();
      const auditDir = log.directory;

      // Write a large amount of data to trigger rotation
      // Create a fake large file first
      const bigData = "x".repeat(1024); // 1KB per detail
      for (let i = 0; i < 10500; i++) {
        log.logSecurityEvent("peer-flood", "test_rotation", { data: bigData });
      }

      // Check that archive files were created
      const files = fs
        .readdirSync(auditDir)
        .filter((f) => f.startsWith("audit-") && f !== "audit.jsonl");
      expect(files.length).toBeGreaterThanOrEqual(1);

      log.close();
    });
  });

  describe("Export", () => {
    it("should export all logs as JSON", () => {
      const log = createAuditLog();
      log.logHandshake("peer-1", "Alice", true);
      log.logMessage("inbound", "peer-1", "Alice", "chat");
      log.logSecurityEvent("peer-2", "unknown_peer");

      const exported = log.exportLogs();
      const entries = JSON.parse(exported);
      expect(entries).toHaveLength(3);
      expect(entries[0].eventType).toBe("handshake");

      log.close();
    });

    it("should filter exports by time range", () => {
      const log = createAuditLog();

      // Use vi.spyOn to control Date.now for deterministic timestamps
      const baseTime = 1700000000000;
      const nowSpy = vi.spyOn(Date, "now");

      nowSpy.mockReturnValue(baseTime);
      log.logHandshake("peer-1", "Alice", true);

      nowSpy.mockReturnValue(baseTime + 5000);
      log.logHandshake("peer-2", "Bob", true);

      nowSpy.mockReturnValue(baseTime + 10000);
      log.logHandshake("peer-3", "Carol", true);

      nowSpy.mockRestore();

      // Export only entries from baseTime+3000 onwards (should get Bob + Carol)
      const exported = log.exportLogs(baseTime + 3000);
      const entries = JSON.parse(exported);
      expect(entries).toHaveLength(2);
      expect(entries[0].peerName).toBe("Bob");
      expect(entries[1].peerName).toBe("Carol");

      // Export only entries up to baseTime+6000 (should get Alice + Bob)
      const exported2 = log.exportLogs(undefined, baseTime + 6000);
      const entries2 = JSON.parse(exported2);
      expect(entries2).toHaveLength(2);
      expect(entries2[0].peerName).toBe("Alice");
      expect(entries2[1].peerName).toBe("Bob");

      log.close();
    });

    it("should export empty array when no logs exist", () => {
      const log = createAuditLog();
      const exported = log.exportLogs();
      expect(JSON.parse(exported)).toEqual([]);

      log.close();
    });
  });

  describe("Reload from Disk", () => {
    it("should pre-populate ring buffer from existing file", () => {
      // Write some entries with first instance
      const log1 = createAuditLog();
      log1.logHandshake("peer-1", "Alice", true);
      log1.logHandshake("peer-2", "Bob", true);
      log1.close();

      // Create new instance — should reload from disk
      const log2 = createAuditLog();
      const recent = log2.getRecentLogs(10);
      expect(recent).toHaveLength(2);

      log2.close();
    });
  });

  describe("Error Resilience", () => {
    it("should handle missing audit directory gracefully", () => {
      const badDir = path.join(tmpDir, "nonexistent", "deep", "path");
      const log = new FederationAuditLog({ stateDir: badDir });

      // Should not throw
      log.logHandshake("peer-1", "Alice", true);

      const recent = log.getRecentLogs(1);
      expect(recent).toHaveLength(1);

      log.close();
    });
  });
});
