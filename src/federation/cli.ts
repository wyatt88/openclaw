/**
 * Federation CLI — `openclaw federation` commands
 *
 * Commands:
 *   openclaw federation status               — Show identity + peers
 *   openclaw federation pair --generate       — Generate pairing code (Instance A)
 *   openclaw federation pair --code ABCDEF    — Join with code (Instance B)
 *   openclaw federation peers                 — List trusted peers
 *   openclaw federation revoke <peerId>       — Revoke peer trust
 *   openclaw federation chat <peerId> [msg]   — Debug: send chat to peer
 *
 * Uses Commander.js (same pattern as other OpenClaw CLI modules).
 */

import type { Command } from "commander";
import { loadOrCreateFederationIdentity, formatPeerId } from "./crypto.js";
import { PairingServer, initiatePairingToServer } from "./pairing-server.js";
import {
  renderPairingDisplay,
  formatPairingResult,
  generateQrPayload,
  type PairingResult,
} from "./pairing.js";
import { TrustStore } from "./trust-store.js";
import type { FederationCapability, PeerEndpoint, TrustedPeer } from "./types.js";

// ─── Helpers ────────────────────────────────────────────────

const FEDERATION_INSTANCE_NAME = process.env.OPENCLAW_FEDERATION_NAME ?? "my-openclaw";

function getIdentity(name?: string) {
  return loadOrCreateFederationIdentity(name ?? FEDERATION_INSTANCE_NAME);
}

function getTrustStore() {
  return new TrustStore();
}

function formatTrustLevel(trust: string): string {
  switch (trust) {
    case "direct":
      return "✅ direct";
    case "vouched":
      return "🤝 vouched";
    case "unknown":
      return "❓ unknown";
    default:
      return trust;
  }
}

function formatTimestamp(ms: number | undefined): string {
  if (!ms) {
    return "never";
  }
  const date = new Date(ms);
  const now = Date.now();
  const diff = now - ms;
  if (diff < 60_000) {
    return "just now";
  }
  if (diff < 3600_000) {
    return `${Math.floor(diff / 60_000)}m ago`;
  }
  if (diff < 86400_000) {
    return `${Math.floor(diff / 3600_000)}h ago`;
  }
  return date.toISOString().slice(0, 16).replace("T", " ");
}

function resolvePeerId(store: TrustStore, idOrPrefix: string): string | null {
  // Direct match
  const direct = store.getPeer(idOrPrefix);
  if (direct) {
    return idOrPrefix;
  }

  // Prefix match (support short IDs like "a7f3" or "oc1_a7f3")
  const cleaned = idOrPrefix.replace(/^oc1_/, "");
  const peers = store.listPeers();
  const matches = peers.filter(
    (p) =>
      p.identity.peerId.startsWith(cleaned) ||
      p.identity.name.toLowerCase() === idOrPrefix.toLowerCase(),
  );

  if (matches.length === 1) {
    return matches[0].identity.peerId;
  }
  if (matches.length > 1) {
    console.error(`Ambiguous peer ID "${idOrPrefix}" — matches:`);
    for (const m of matches) {
      console.error(`  ${formatPeerId(m.identity.peerId)} (${m.identity.name})`);
    }
    return null;
  }
  return null;
}

// ─── Registration ───────────────────────────────────────────

/**
 * Register the `openclaw federation` CLI commands.
 */
export function registerFederationCli(program: Command): void {
  const fed = program
    .command("federation")
    .description("Federation: peer-to-peer trust, pairing, and communication")
    .alias("fed");

  // ─── status ─────────────────────────────────────────────
  fed
    .command("status")
    .description("Show local federation identity and connected peers")
    .option("--json", "Output as JSON", false)
    .action(async (opts) => {
      const identity = getIdentity();
      const store = getTrustStore();
      const peers = store.listPeers();
      const trusted = peers.filter((p) => p.trust === "direct" || p.trust === "vouched");
      const connected = peers.filter((p) => p.connected);

      if (opts.json) {
        console.log(
          JSON.stringify(
            {
              identity: {
                peerId: identity.peerId,
                name: identity.name,
                publicKeyPem: identity.publicKeyPem,
              },
              peers: peers.map(formatPeerJson),
              totalPeers: peers.length,
              totalTrusted: trusted.length,
              totalConnected: connected.length,
            },
            null,
            2,
          ),
        );
        return;
      }

      console.log("");
      console.log("🌐 Federation Identity");
      console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
      console.log(`  Name:     ${identity.name}`);
      console.log(`  Peer ID:  ${formatPeerId(identity.peerId)}`);
      console.log(`  Full ID:  ${identity.peerId}`);
      console.log("");
      console.log(
        `  Peers: ${peers.length} total, ${trusted.length} trusted, ${connected.length} connected`,
      );

      if (peers.length > 0) {
        console.log("");
        console.log("  Trusted Peers:");
        for (const peer of peers) {
          const status = peer.connected ? "🟢" : "⚪";
          console.log(
            `    ${status} ${peer.identity.name} (${formatPeerId(peer.identity.peerId)}) — ${formatTrustLevel(peer.trust)}`,
          );
        }
      }
      console.log("");
    });

  // ─── pair ───────────────────────────────────────────────
  fed
    .command("pair")
    .description("Start or join a pairing session with another OpenClaw instance")
    .option("--generate", "Generate a new pairing code (server mode)")
    .option("--code <code>", "Join with a pairing code (client mode)")
    .option("--url <url>", "Pairing server URL (for client mode)")
    .option("--port <port>", "Port for pairing server", "0")
    .option("--timeout <seconds>", "Pairing timeout in seconds", "60")
    .option("--name <name>", "Instance name override")
    .option("--capabilities <caps>", "Comma-separated capabilities to grant", "chat")
    .option("--auto-accept", "Auto-accept pairing requests (no confirmation prompt)", false)
    .option("--json", "Output as JSON", false)
    .action(async (opts) => {
      const identity = getIdentity(opts.name);
      const store = getTrustStore();
      const timeoutMs = Number(opts.timeout) * 1000;
      const capabilities = opts.capabilities
        .split(",")
        .map((c: string) => c.trim()) as FederationCapability[];

      if (opts.code) {
        // ── Client mode (Instance B) ────────────────────
        await handlePairClient({
          identity,
          store,
          setupCode: opts.code,
          serverUrl: opts.url,
          capabilities,
          timeoutMs,
          json: opts.json,
        });
      } else {
        // ── Server mode (Instance A) — default or --generate
        await handlePairServer({
          identity,
          store,
          port: Number(opts.port),
          timeoutMs,
          capabilities,
          autoAccept: opts.autoAccept,
          json: opts.json,
        });
      }
    });

  // ─── peers ──────────────────────────────────────────────
  fed
    .command("peers")
    .description("List all trusted peers")
    .option("--json", "Output as JSON", false)
    .option("--verbose", "Show full peer details", false)
    .action(async (opts) => {
      const store = getTrustStore();
      const peers = store.listPeers();

      if (opts.json) {
        console.log(JSON.stringify(peers.map(formatPeerJson), null, 2));
        return;
      }

      if (peers.length === 0) {
        console.log("\n  No peers configured.");
        console.log("  Run `openclaw federation pair` to connect with another instance.\n");
        return;
      }

      console.log("");
      console.log(`🤝 Federation Peers (${peers.length})`);
      console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

      for (const peer of peers) {
        const status = peer.connected ? "🟢 connected" : "⚪ offline";
        console.log("");
        console.log(`  ${peer.identity.name}`);
        console.log(`    ID:           ${formatPeerId(peer.identity.peerId)}`);
        console.log(`    Status:       ${status}`);
        console.log(`    Trust:        ${formatTrustLevel(peer.trust)}`);
        console.log(`    Added:        ${formatTimestamp(peer.addedAt)}`);
        console.log(`    Last seen:    ${formatTimestamp(peer.lastSeenAt)}`);
        console.log(`    Capabilities: ${peer.grantedCapabilities.capabilities.join(", ")}`);

        if (opts.verbose) {
          console.log(`    Full ID:      ${peer.identity.peerId}`);
          if (peer.endpoint.wsUrl) {
            console.log(`    WS URL:       ${peer.endpoint.wsUrl}`);
          }
          if (peer.endpoint.httpUrl) {
            console.log(`    HTTP URL:     ${peer.endpoint.httpUrl}`);
          }
          if (peer.endpoint.tailnetHostname) {
            console.log(`    Tailnet:      ${peer.endpoint.tailnetHostname}`);
          }
          if (peer.vouchedBy) {
            console.log(`    Vouched by:   ${formatPeerId(peer.vouchedBy)}`);
          }
        }
      }
      console.log("");
    });

  // ─── revoke ─────────────────────────────────────────────
  fed
    .command("revoke <peerId>")
    .description("Revoke trust for a peer (remove from trust store)")
    .option("--yes", "Skip confirmation prompt", false)
    .action(async (peerId: string, opts) => {
      const store = getTrustStore();
      const resolved = resolvePeerId(store, peerId);

      if (!resolved) {
        console.error(`\n  ❌ Peer not found: ${peerId}`);
        console.error("  Use `openclaw federation peers` to list known peers.\n");
        process.exit(1);
        return;
      }

      const peer = store.getPeer(resolved)!;

      if (!opts.yes) {
        console.log(`\n  Revoking trust for: ${peer.identity.name} (${formatPeerId(resolved)})`);
        console.log("  This will remove the peer from your trust store.");
        console.log("  The peer will need to re-pair to communicate again.\n");

        // Simple confirmation via stdin
        const confirmed = await promptConfirmation("  Proceed? [y/N] ");
        if (!confirmed) {
          console.log("  Cancelled.");
          return;
        }
      }

      const removed = store.removePeer(resolved);
      if (removed) {
        console.log(`\n  ✅ Revoked trust for ${peer.identity.name} (${formatPeerId(resolved)})`);
      } else {
        console.error(`\n  ❌ Failed to remove peer.`);
      }
      console.log("");
    });

  // ─── chat ───────────────────────────────────────────────
  fed
    .command("chat <peerId> [message...]")
    .description("Send a debug chat message to a peer (via federation client)")
    .option("--conversation <id>", "Conversation ID")
    .action(async (peerId: string, messageParts: string[], opts) => {
      const store = getTrustStore();
      const resolved = resolvePeerId(store, peerId);

      if (!resolved) {
        console.error(`\n  ❌ Peer not found: ${peerId}`);
        console.error("  Use `openclaw federation peers` to list known peers.\n");
        process.exit(1);
        return;
      }

      const peer = store.getPeer(resolved)!;
      const text = messageParts.join(" ");

      if (!text) {
        console.error("\n  ❌ No message provided.");
        console.error("  Usage: openclaw federation chat <peerId> <message>\n");
        process.exit(1);
        return;
      }

      if (!peer.connected) {
        console.error(`\n  ⚠️  Peer ${peer.identity.name} is not currently connected.`);
        console.error("  The message will be queued if the transport supports it.\n");
      }

      console.log(`\n  📤 Sending to ${peer.identity.name} (${formatPeerId(resolved)}):`);
      console.log(`  > ${text}`);
      console.log("");

      // Note: Actual message transport requires the FederationNode to be running.
      // This CLI command constructs the signed message for debugging purposes.
      const identity = getIdentity();
      const { FederationNode } = await import("./client.js");
      const node = new FederationNode({
        enabled: true,
        instanceName: identity.name,
      });

      const result = node.createChatMessage({
        peerId: resolved,
        text,
        conversationId: opts.conversation,
      });

      if (!result.ok) {
        console.error(`  ❌ ${(result as { ok: false; error: string }).error}`);
        process.exit(1);
        return;
      }

      const chatResult = result as { ok: true; message: unknown; conversationId: string };
      console.log(`  ✅ Message signed (conversation: ${chatResult.conversationId})`);
      console.log("  📝 Note: Delivery requires a running gateway with federation enabled.\n");
    });
}

// ─── Pairing Flow Handlers ──────────────────────────────────

async function handlePairServer(params: {
  identity: ReturnType<typeof getIdentity>;
  store: TrustStore;
  port: number;
  timeoutMs: number;
  capabilities: FederationCapability[];
  autoAccept: boolean;
  json: boolean;
}): Promise<void> {
  const server = new PairingServer({
    port: params.port,
    identity: params.identity,
    trustStore: params.store,
    defaultCapabilities: params.capabilities,
    timeoutMs: params.timeoutMs,
    onPairingRequest: params.autoAccept
      ? async () => true
      : async (session) => {
          if (!session.remoteIdentity) {
            return false;
          }
          console.log("");
          console.log("  📥 Incoming pairing request!");
          console.log(
            `  From: ${session.remoteIdentity.name} (${formatPeerId(session.remoteIdentity.peerId)})`,
          );
          console.log("");
          return await promptConfirmation("  Accept this peer? [y/N] ");
        },
    onPairingComplete: (result) => {
      if (params.json) {
        console.log(
          JSON.stringify({
            ok: true,
            peerId: result.peerId,
            peerName: result.peerName,
            capabilities: result.grantedCapabilities,
          }),
        );
      } else {
        console.log("");
        console.log(formatPairingResult(result));
        console.log("");
      }
    },
    onLog: (msg) => {
      if (!params.json) {
        console.log(`  ℹ️  ${msg}`);
      }
    },
  });

  try {
    const { session, port, url } = await server.start();

    if (params.json) {
      console.log(
        JSON.stringify({
          status: "waiting",
          setupCode: session.setupCode,
          port,
          url,
          peerId: params.identity.peerId,
          instanceName: params.identity.name,
          timeoutMs: params.timeoutMs,
        }),
      );
    } else {
      console.log("");
      console.log(
        renderPairingDisplay({
          setupCode: session.setupCode,
          peerId: params.identity.peerId,
          instanceName: params.identity.name,
          endpoint: url,
        }),
      );
      console.log("");
      console.log(`  On the other instance, run:`);
      console.log(`  $ openclaw federation pair --code ${session.setupCode} --url ${url}`);
      console.log("");

      // Also show the QR payload for potential QR scanning
      const qrData = generateQrPayload({
        setupCode: session.setupCode,
        publicKeyPem: params.identity.publicKeyPem,
        endpoint: `${url}/federation/pair`,
        instanceName: params.identity.name,
      });
      console.log(`  QR data: ${qrData}`);
      console.log("");
    }

    // Wait for completion
    const result = await server.waitForCompletion();
    if (!result && !params.json) {
      console.log("  ⏰ Pairing session expired or was cancelled.\n");
    }
  } catch (err) {
    console.error(`\n  ❌ ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  } finally {
    await server.stop();
  }
}

async function handlePairClient(params: {
  identity: ReturnType<typeof getIdentity>;
  store: TrustStore;
  setupCode: string;
  serverUrl?: string;
  capabilities: FederationCapability[];
  timeoutMs: number;
  json: boolean;
}): Promise<void> {
  if (!params.serverUrl) {
    console.error("\n  ❌ --url is required in client mode.");
    console.error("  Usage: openclaw federation pair --code ABCDEF --url http://host:port\n");
    process.exit(1);
    return;
  }

  if (!params.json) {
    console.log(`\n  🔗 Connecting to ${params.serverUrl}...`);
    console.log(`  📝 Using setup code: ${params.setupCode}\n`);
  }

  const localEndpoint: PeerEndpoint = {};
  try {
    const os = await import("node:os");
    const hostname = os.hostname();
    if (hostname.endsWith(".ts.net")) {
      localEndpoint.tailnetHostname = hostname;
    }
  } catch {
    // ignore
  }

  const result = await initiatePairingToServer({
    serverUrl: params.serverUrl,
    setupCode: params.setupCode,
    identity: params.identity,
    trustStore: params.store,
    localEndpoint,
    capabilities: params.capabilities,
    timeoutMs: params.timeoutMs,
  });

  if (!result.ok) {
    const errMsg = (result as { ok: false; error: string }).error;
    if (params.json) {
      console.log(JSON.stringify({ ok: false, error: errMsg }));
    } else {
      console.error(`\n  ❌ Pairing failed: ${errMsg}\n`);
    }
    process.exit(1);
    return;
  }

  const pairingResult = (result as { ok: true; result: PairingResult }).result;

  if (params.json) {
    console.log(
      JSON.stringify({
        ok: true,
        peerId: pairingResult.peerId,
        peerName: pairingResult.peerName,
        capabilities: pairingResult.grantedCapabilities,
      }),
    );
  } else {
    console.log("");
    console.log(formatPairingResult(pairingResult));
    console.log("");
  }
}

// ─── Utility ────────────────────────────────────────────────

function formatPeerJson(peer: TrustedPeer) {
  return {
    peerId: peer.identity.peerId,
    peerIdShort: formatPeerId(peer.identity.peerId),
    name: peer.identity.name,
    trust: peer.trust,
    connected: peer.connected,
    capabilities: peer.grantedCapabilities.capabilities,
    endpoint: peer.endpoint,
    addedAt: peer.addedAt,
    lastSeenAt: peer.lastSeenAt,
    vouchedBy: peer.vouchedBy,
  };
}

function promptConfirmation(prompt: string): Promise<boolean> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    const stdin = process.stdin;
    stdin.setEncoding("utf8");
    stdin.once("data", (data) => {
      const answer = (data as string).trim().toLowerCase();
      resolve(answer === "y" || answer === "yes");
    });
    // Handle non-interactive (pipe) — default to no
    if (!stdin.isTTY) {
      resolve(false);
    }
  });
}
