/**
 * Federation CLI — `openclaw federation` commands
 *
 * Commands:
 *   openclaw federation status               — Show identity + peers + stats
 *   openclaw federation pair --generate       — Generate OC- pairing code (with endpoint)
 *   openclaw federation pair --code OC-xxxx   — Join with OC- pairing code
 *   openclaw federation peers                 — List trusted peers (table format)
 *   openclaw federation revoke <peerId>       — Revoke peer trust
 *   openclaw federation chat <peerId> [msg]   — Debug: send chat to peer
 *
 * Uses Commander.js (same pattern as other OpenClaw CLI modules).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import chalk from "chalk";
import type { Command } from "commander";
import { callGateway } from "../gateway/call.js";
import { GATEWAY_CLIENT_MODES, GATEWAY_CLIENT_NAMES } from "../utils/message-channel.js";
import { loadOrCreateFederationIdentity, formatPeerId } from "./crypto.js";
import { PairingServer, initiatePairingToServer } from "./pairing-server.js";
import {
  PairingManager,
  renderPairingDisplay,
  formatPairingResult,
  generateQrPayload,
  decodePairingCode,
  type PairingResult,
} from "./pairing.js";
import { TrustStore } from "./trust-store.js";
import type { FederationCapability, PeerEndpoint, TrustedPeer } from "./types.js";

// ─── Helpers ────────────────────────────────────────────────

/**
 * Lightweight config reader — reads openclaw.json directly without
 * the heavy `loadConfig()` pipeline (avoids IncludeProcessor, etc.).
 */
function readFederationConfig(): { instanceName?: string; endpoint?: string } {
  try {
    const home =
      process.env.OPENCLAW_HOME ??
      path.join(process.env.HOME ?? process.env.USERPROFILE ?? ".", ".openclaw");
    const configPath = process.env.OPENCLAW_CONFIG_PATH ?? path.join(home, "openclaw.json");
    const raw = JSON.parse(fs.readFileSync(configPath, "utf8")) as {
      federation?: { instanceName?: string; endpoint?: string };
    };
    return raw.federation ?? {};
  } catch {
    return {};
  }
}

function resolveFederationInstanceName(): string {
  if (process.env.OPENCLAW_FEDERATION_NAME) {
    return process.env.OPENCLAW_FEDERATION_NAME;
  }
  const cfg = readFederationConfig();
  return cfg.instanceName || "my-openclaw";
}

const FEDERATION_INSTANCE_NAME = resolveFederationInstanceName();

function getIdentity(name?: string) {
  return loadOrCreateFederationIdentity(name ?? FEDERATION_INSTANCE_NAME);
}

function getTrustStore() {
  return new TrustStore();
}

function _formatTrustLevel(trust: string): string {
  switch (trust) {
    case "direct":
      return chalk.green("✅ direct");
    case "vouched":
      return chalk.yellow("🤝 vouched");
    case "unknown":
      return chalk.gray("❓ unknown");
    default:
      return trust;
  }
}

function formatTimestamp(ms: number | undefined): string {
  if (!ms) {
    return chalk.gray("never");
  }
  const now = Date.now();
  const diff = now - ms;
  if (diff < 60_000) {
    return chalk.green("just now");
  }
  if (diff < 3600_000) {
    return `${Math.floor(diff / 60_000)}m ago`;
  }
  if (diff < 86400_000) {
    return `${Math.floor(diff / 3600_000)}h ago`;
  }
  const date = new Date(ms);
  return date.toISOString().slice(0, 16).replace("T", " ");
}

/**
 * Format a duration in ms to human-readable (e.g. "2h 34m").
 */
function _formatDuration(ms: number): string {
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  const d = Math.floor(h / 24);
  if (d > 0) {
    return `${d}d ${h % 24}h`;
  }
  if (h > 0) {
    return `${h}h ${m % 60}m`;
  }
  if (m > 0) {
    return `${m}m ${s % 60}s`;
  }
  return `${s}s`;
}

/**
 * Format auth method from peer info.
 */
function formatAuthMethod(peer: TrustedPeer): string {
  if (peer.trust === "direct") {
    return "ed25519";
  }
  if (peer.trust === "vouched") {
    return "vouched";
  }
  return "unknown";
}

/**
 * Pad string to fixed width (accounting for invisible ANSI codes).
 */
function padRight(str: string, width: number): string {
  // Strip ANSI codes for length calculation
  // eslint-disable-next-line no-control-regex
  const stripped = str.replace(/\x1b\[[0-9;]*m/g, "");
  const pad = Math.max(0, width - stripped.length);
  return str + " ".repeat(pad);
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

// ─── Gateway RPC Helper ─────────────────────────────────────

type GatewayRpcOpts = {
  url?: string;
  token?: string;
};

/**
 * Call the running Gateway via RPC to get live federation status.
 * Falls back to local trust store if the Gateway is unreachable.
 */
async function callFederationRpc(
  method: string,
  opts?: GatewayRpcOpts,
  _params?: unknown,
): Promise<{ ok: boolean; [key: string]: unknown } | null> {
  // Read config for token and port
  let token = opts?.token;
  let port = 18789;
  try {
    const raw = JSON.parse(
      fs.readFileSync(path.join(process.env.HOME ?? "", ".openclaw", "openclaw.json"), "utf-8"),
    );
    if (!token) {
      token = raw?.gateway?.auth?.token ?? raw?.gateway?.remote?.token;
    }
    if (raw?.gateway?.port) {
      port = raw.gateway.port;
    }
  } catch {
    // ignore
  }

  // Map RPC method names to HTTP API paths
  const httpPath =
    method === "federation.listPeers"
      ? "/api/federation/peers"
      : method === "federation.status"
        ? "/api/federation/status"
        : null;

  // Prefer HTTP API -- avoids Gateway WS handshake timeout issues
  if (httpPath && token) {
    try {
      const baseUrl = opts?.url
        ? opts.url.replace("ws://", "http://").replace("wss://", "https://")
        : `http://127.0.0.1:${port}`;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 5_000);
      const res = await fetch(`${baseUrl}${httpPath}`, {
        headers: { Authorization: `Bearer ${token}` },
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (res.ok) {
        const data = (await res.json()) as { ok?: boolean; [key: string]: unknown };
        return { ok: true, ...data };
      }
    } catch {
      // HTTP failed, fall through to WS RPC
    }
  }

  // Fallback: WS RPC (may hit Gateway 3s handshake timeout)
  try {
    const result = await callGateway({
      url: opts?.url,
      token,
      method,
      params: _params ?? {},
      timeoutMs: 8_000,
      connectDelayMs: 5_000,
      clientName: GATEWAY_CLIENT_NAMES.CLI,
      mode: GATEWAY_CLIENT_MODES.CLI,
    });
    return result as { ok: boolean; [key: string]: unknown };
  } catch {
    return null;
  }
}

// ─── Registration ───────────────────────────────────────────

/**
 * Register the `openclaw federation` CLI commands.
 */
export function registerFederationCli(program: Command): void {
  const fed = program
    .command("federation")
    .description("Federation: peer-to-peer trust, pairing, and communication")
    .alias("fed")
    .hook("postAction", () => {
      // Ensure CLI exits after async actions complete (WS connections keep the event loop alive)
      process.exit(0);
    });

  // ─── status ─────────────────────────────────────────────
  fed
    .command("status")
    .description("Show local federation identity, connectivity, and stats")
    .option("--json", "Output as JSON", false)
    .option("--url <url>", "Gateway WebSocket URL")
    .option("--token <token>", "Gateway token")
    .option("--offline", "Read from local trust store only (skip Gateway RPC)", false)
    .action(async (opts) => {
      const identity = getIdentity();

      // Try to get live status from the running Gateway
      let liveStatus: { ok: boolean; [key: string]: unknown } | null = null;
      if (!opts.offline) {
        liveStatus = await callFederationRpc("federation.status", {
          url: opts.url,
          token: opts.token,
        });
      }

      if (liveStatus?.ok) {
        // ── Live status from Gateway ──────────────────
        const status = liveStatus.status as {
          enabled: boolean;
          identity: { peerId: string; name: string };
          peers: Array<{
            peerId: string;
            peerIdFull?: string;
            peerName: string;
            connected: boolean;
            trust: string;
            endpoint?: string;
            capabilities: string[];
            lastSeenAt?: number;
            connectionPhase?: string;
            connectionDirection?: string;
          }>;
          totalConnected: number;
          totalTrusted: number;
        };
        const transportInfo = liveStatus.transport as {
          activeConnections: number;
        };

        if (opts.json) {
          console.log(JSON.stringify(liveStatus, null, 2));
          return;
        }

        const peers = status.peers ?? [];
        const connected = peers.filter((p) => p.connected);

        const statusLabel =
          connected.length > 0
            ? chalk.green.bold("ACTIVE")
            : peers.length > 0
              ? chalk.yellow.bold("IDLE")
              : chalk.gray.bold("UNCONFIGURED");

        console.log("");
        console.log(`  Federation Status: ${statusLabel} ${chalk.dim("(live)")}`);
        console.log("");
        console.log(`  ${chalk.dim("Instance:")}   ${chalk.bold(status.identity.name)}`);
        console.log(`  ${chalk.dim("Peer ID:")}    ${chalk.cyan(status.identity.peerId)}`);
        console.log(`  ${chalk.dim("Peers:")}      ${connected.length}/${peers.length} connected`);
        console.log(
          `  ${chalk.dim("Transport:")}  ${transportInfo?.activeConnections ?? 0} active WS connection(s)`,
        );

        // Show endpoint if configured
        const endpoint = process.env.OPENCLAW_FEDERATION_ENDPOINT;
        if (endpoint) {
          console.log(`  ${chalk.dim("Endpoint:")}   ${chalk.cyan(endpoint)}`);
        }

        if (peers.length > 0) {
          console.log("");
          console.log(chalk.dim("  Peers:"));
          for (const peer of peers) {
            const pStatus = peer.connected ? chalk.green("● connected") : chalk.gray("○ offline");
            const dir = peer.connectionDirection ? chalk.dim(` [${peer.connectionDirection}]`) : "";
            console.log(
              `    ${pStatus}${dir}  ${chalk.bold(peer.peerName)} ${chalk.dim("(" + peer.peerId + ")")}`,
            );
          }
        }
        console.log("");
        return;
      }

      // ── Fallback: local trust store ───────────────────
      const store = getTrustStore();
      const peers = store.listPeers();
      const trusted = peers.filter((p) => p.trust === "direct" || p.trust === "vouched");
      const connected = peers.filter((p) => p.connected);
      const introduced = peers.filter((p) => p.trust === "vouched");

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
              source: "local",
            },
            null,
            2,
          ),
        );
        return;
      }

      // Determine federation status
      const statusLabel =
        connected.length > 0
          ? chalk.green.bold("ACTIVE")
          : peers.length > 0
            ? chalk.yellow.bold("IDLE")
            : chalk.gray.bold("UNCONFIGURED");

      console.log("");
      console.log(
        `  Federation Status: ${statusLabel} ${chalk.dim("(offline — Gateway not reachable)")}`,
      );
      console.log("");
      console.log(`  ${chalk.dim("Instance:")}   ${chalk.bold(identity.name)}`);
      console.log(`  ${chalk.dim("Peer ID:")}    ${chalk.cyan(formatPeerId(identity.peerId))}`);
      console.log(`  ${chalk.dim("Full ID:")}    ${chalk.gray(identity.peerId)}`);

      // Show endpoint if configured
      const endpoint = process.env.OPENCLAW_FEDERATION_ENDPOINT;
      if (endpoint) {
        console.log(`  ${chalk.dim("Endpoint:")}   ${chalk.cyan(endpoint)}`);
      }

      console.log(`  ${chalk.dim("Peers:")}      ${connected.length}/${peers.length} connected`);
      console.log("");
      console.log(
        `  ${chalk.dim("Trust Store:")} ${trusted.length} peers, ${introduced.length} introduced`,
      );
      console.log(`  ${chalk.dim("Identity:")}    Ed25519`);

      if (peers.length > 0) {
        console.log("");
        console.log(chalk.dim("  Trusted Peers:"));
        for (const peer of peers) {
          const status = peer.connected ? chalk.green("● connected") : chalk.gray("○ offline");
          console.log(
            `    ${status}  ${chalk.bold(peer.identity.name)} ${chalk.dim("(" + formatPeerId(peer.identity.peerId) + ")")}`,
          );
        }
      }
      console.log("");
    });

  // ─── pair ───────────────────────────────────────────────
  fed
    .command("pair")
    .description("Start or join a pairing session with another OpenClaw instance")
    .option("--generate", "Generate a new OC- pairing code")
    .option("--code <code>", "Join with an OC- pairing code")
    .option("--endpoint <url>", "Federation endpoint (overrides config federation.endpoint)")
    .option("--url <url>", "Pairing server URL (legacy client mode)")
    .option("--port <port>", "Port for pairing server", "0")
    .option("--timeout <seconds>", "Pairing timeout in seconds", "300")
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

      if (opts.generate) {
        // ── OC- Code Generation (new flow) ──────────────
        // Resolve endpoint: CLI flag > config > error
        let endpoint = opts.endpoint as string | undefined;
        if (!endpoint) {
          endpoint = readFederationConfig().endpoint;
        }
        if (!endpoint) {
          if (opts.json) {
            console.log(
              JSON.stringify({
                ok: false,
                error:
                  "No endpoint specified. Use --endpoint or set federation.endpoint in openclaw.json",
              }),
            );
          } else {
            console.error(chalk.red("\n  ❌ No endpoint specified."));
            console.error(
              chalk.gray(
                "  Use --endpoint wss://... or set federation.endpoint in openclaw.json\n",
              ),
            );
          }
          process.exit(1);
          return;
        }
        await handlePairGenerate({
          identity,
          store,
          endpoint,
          timeoutMs,
          capabilities,
          json: opts.json,
        });
      } else if (opts.code && opts.code.startsWith("OC-")) {
        // ── OC- Code Acceptance (new flow) ──────────────
        await handlePairWithCode({
          identity,
          store,
          code: opts.code,
          endpoint: opts.endpoint,
          capabilities,
          json: opts.json,
        });
      } else if (opts.code) {
        // ── Legacy client mode (6-digit setup code) ─────
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
        // ── Legacy server mode ──────────────────────────
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
    .description("List all trusted peers in a table view")
    .option("--json", "Output as JSON", false)
    .option("--verbose", "Show full peer details", false)
    .option("--url <url>", "Gateway WebSocket URL")
    .option("--token <token>", "Gateway token")
    .option("--offline", "Read from local trust store only (skip Gateway RPC)", false)
    .action(async (opts) => {
      // Try to get live status from the running Gateway
      let livePeers: { ok: boolean; [key: string]: unknown } | null = null;
      if (!opts.offline) {
        livePeers = await callFederationRpc("federation.listPeers", {
          url: opts.url,
          token: opts.token,
        });
      }

      if (livePeers?.ok) {
        // ── Live data from Gateway ────────────────────
        const _thisInstance = livePeers.thisInstance as { peerId: string; name: string };
        const peers = livePeers.peers as Array<{
          peerId: string;
          peerIdFull?: string;
          name: string;
          trust: string;
          connected: boolean;
          endpoint?: string;
          capabilities: string[];
          lastSeenAt?: string | null;
          connectionPhase?: string;
          connectionDirection?: string;
          connectedAt?: string | null;
        }>;
        const summary = livePeers.summary as {
          total: number;
          connected: number;
          trusted: number;
        };

        if (opts.json) {
          console.log(JSON.stringify(livePeers, null, 2));
          return;
        }

        if (peers.length === 0) {
          console.log("");
          console.log(chalk.gray("  No peers configured."));
          console.log(
            chalk.gray("  Run ") +
              chalk.cyan("openclaw federation pair --generate --endpoint <url>") +
              chalk.gray(" to start pairing."),
          );
          console.log("");
          return;
        }

        const connected = summary?.connected ?? peers.filter((p) => p.connected).length;
        const offline = (summary?.total ?? peers.length) - connected;

        console.log("");
        const parts: string[] = [];
        if (connected > 0) {
          parts.push(chalk.green(`${connected} connected`));
        }
        if (offline > 0) {
          parts.push(chalk.gray(`${offline} offline`));
        }
        console.log(`  Federation Peers (${parts.join(", ")}) ${chalk.dim("— live")}:`);
        console.log("");

        // Table header
        const cols = {
          name: 10,
          status: 13,
          endpoint: 38,
          direction: 10,
          auth: 9,
          lastSeen: 12,
        };

        console.log(
          chalk.dim("  ") +
            padRight(chalk.bold("Name"), cols.name) +
            padRight(chalk.bold("Status"), cols.status) +
            padRight(chalk.bold("Endpoint"), cols.endpoint) +
            padRight(chalk.bold("Dir"), cols.direction) +
            padRight(chalk.bold("Auth"), cols.auth) +
            chalk.bold("Last Seen"),
        );

        // Separator
        console.log(
          chalk.dim("  ") +
            chalk.dim("──────".padEnd(cols.name)) +
            chalk.dim("──────────".padEnd(cols.status)) +
            chalk.dim("──────────────────────────────".padEnd(cols.endpoint)) +
            chalk.dim("────────".padEnd(cols.direction)) +
            chalk.dim("───────".padEnd(cols.auth)) +
            chalk.dim("──────────"),
        );

        // Peer rows
        for (const peer of peers) {
          const name = chalk.bold(peer.name.slice(0, cols.name - 2));
          const status = peer.connected ? chalk.green("● connected") : chalk.gray("○ offline");
          const ep = peer.endpoint ?? chalk.gray("-");
          const dir = peer.connectionDirection
            ? chalk.cyan(peer.connectionDirection)
            : chalk.gray("-");
          const auth = peer.trust === "direct" ? "ed25519" : peer.trust;
          const lastSeen = peer.lastSeenAt
            ? formatTimestamp(new Date(peer.lastSeenAt).getTime())
            : chalk.gray("never");

          console.log(
            "  " +
              padRight(name, cols.name) +
              padRight(status, cols.status) +
              padRight(ep.slice(0, cols.endpoint - 2), cols.endpoint) +
              padRight(dir, cols.direction) +
              padRight(auth, cols.auth) +
              lastSeen,
          );

          if (opts.verbose) {
            console.log(chalk.dim(`           ID: ${peer.peerIdFull ?? peer.peerId}`));
            console.log(
              chalk.dim(`           Trust: ${peer.trust}   Caps: ${peer.capabilities.join(", ")}`),
            );
            if (peer.connectionPhase) {
              console.log(chalk.dim(`           Phase: ${peer.connectionPhase}`));
            }
          }
        }
        console.log("");
        return;
      }

      // ── Fallback: local trust store ───────────────────
      const store = getTrustStore();
      const peers = store.listPeers();

      if (opts.json) {
        console.log(JSON.stringify(peers.map(formatPeerJson), null, 2));
        return;
      }

      if (peers.length === 0) {
        console.log("");
        console.log(chalk.gray("  No peers configured."));
        console.log(
          chalk.gray("  Run ") +
            chalk.cyan("openclaw federation pair --generate --endpoint <url>") +
            chalk.gray(" to start pairing."),
        );
        console.log("");
        return;
      }

      // Count connected / offline
      const connected = peers.filter((p) => p.connected).length;
      const offline = peers.length - connected;

      console.log("");
      const parts: string[] = [];
      if (connected > 0) {
        parts.push(chalk.green(`${connected} connected`));
      }
      if (offline > 0) {
        parts.push(chalk.gray(`${offline} offline`));
      }
      console.log(
        `  Federation Peers (${parts.join(", ")}) ${chalk.dim("— offline (Gateway not reachable)")}:`,
      );
      console.log("");

      // Table header
      const cols = {
        name: 10,
        status: 13,
        endpoint: 38,
        latency: 9,
        auth: 9,
        lastSeen: 12,
      };

      console.log(
        chalk.dim("  ") +
          padRight(chalk.bold("Name"), cols.name) +
          padRight(chalk.bold("Status"), cols.status) +
          padRight(chalk.bold("Endpoint"), cols.endpoint) +
          padRight(chalk.bold("Latency"), cols.latency) +
          padRight(chalk.bold("Auth"), cols.auth) +
          chalk.bold("Last Seen"),
      );

      // Separator
      console.log(
        chalk.dim("  ") +
          chalk.dim("──────".padEnd(cols.name)) +
          chalk.dim("──────────".padEnd(cols.status)) +
          chalk.dim("──────────────────────────────".padEnd(cols.endpoint)) +
          chalk.dim("───────".padEnd(cols.latency)) +
          chalk.dim("───────".padEnd(cols.auth)) +
          chalk.dim("──────────"),
      );

      // Peer rows
      for (const peer of peers) {
        const name = chalk.bold(peer.identity.name.slice(0, cols.name - 2));
        const status = peer.connected ? chalk.green("● connected") : chalk.gray("○ offline");
        const ep =
          peer.endpoint.wsUrl ??
          peer.endpoint.httpUrl ??
          peer.endpoint.tailnetHostname ??
          chalk.gray("-");
        const latency = peer.connected ? chalk.cyan("-") : chalk.gray("-");
        const auth = formatAuthMethod(peer);
        const lastSeen = formatTimestamp(peer.lastSeenAt);

        console.log(
          "  " +
            padRight(name, cols.name) +
            padRight(status, cols.status) +
            padRight(ep.slice(0, cols.endpoint - 2), cols.endpoint) +
            padRight(latency, cols.latency) +
            padRight(auth, cols.auth) +
            lastSeen,
        );

        if (opts.verbose) {
          console.log(chalk.dim(`           ID: ${peer.identity.peerId}`));
          console.log(
            chalk.dim(
              `           Trust: ${peer.trust}   Caps: ${peer.grantedCapabilities.capabilities.join(", ")}`,
            ),
          );
          if (peer.vouchedBy) {
            console.log(chalk.dim(`           Vouched by: ${formatPeerId(peer.vouchedBy)}`));
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
        console.error(chalk.red(`\n  ❌ Peer not found: ${peerId}`));
        console.error(chalk.gray("  Use `openclaw federation peers` to list known peers.\n"));
        process.exit(1);
        return;
      }

      const peer = store.getPeer(resolved)!;

      if (!opts.yes) {
        console.log(
          `\n  Revoking trust for: ${chalk.bold(peer.identity.name)} (${chalk.cyan(formatPeerId(resolved))})`,
        );
        console.log("  This will remove the peer from your trust store.");
        console.log("  The peer will need to re-pair to communicate again.\n");

        const confirmed = await promptConfirmation("  Proceed? [y/N] ");
        if (!confirmed) {
          console.log("  Cancelled.");
          return;
        }
      }

      const removed = store.removePeer(resolved);
      if (removed) {
        console.log(
          chalk.green(`\n  ✓ Revoked trust for ${peer.identity.name} (${formatPeerId(resolved)})`),
        );
      } else {
        console.error(chalk.red(`\n  ❌ Failed to remove peer.`));
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
        console.error(chalk.red(`\n  ❌ Peer not found: ${peerId}`));
        console.error(chalk.gray("  Use `openclaw federation peers` to list known peers.\n"));
        process.exit(1);
        return;
      }

      const peer = store.getPeer(resolved)!;
      const text = messageParts.join(" ");

      if (!text) {
        console.error(chalk.red("\n  ❌ No message provided."));
        console.error(chalk.gray("  Usage: openclaw federation chat <peerId> <message>\n"));
        process.exit(1);
        return;
      }

      if (!peer.connected) {
        console.error(
          chalk.yellow(`\n  ⚠️  Peer ${peer.identity.name} is not currently connected.`),
        );
        console.error(chalk.gray("  The message will be queued if the transport supports it.\n"));
      }

      console.log(
        `\n  📤 Sending to ${chalk.bold(peer.identity.name)} (${chalk.cyan(formatPeerId(resolved))}):`,
      );
      console.log(`  > ${text}`);
      console.log("");

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
        console.error(chalk.red(`  ❌ ${(result as { ok: false; error: string }).error}`));
        process.exit(1);
        return;
      }

      const chatResult = result as { ok: true; message: unknown; conversationId: string };
      console.log(
        chalk.green(`  ✓ Message signed`) +
          chalk.dim(` (conversation: ${chatResult.conversationId})`),
      );
      console.log(
        chalk.gray("  📝 Note: Delivery requires a running gateway with federation enabled.\n"),
      );
    });
}

// ─── New OC- Code Pairing Handlers ──────────────────────────

/**
 * Generate an OC- pairing code with embedded endpoint.
 * `openclaw federation pair --generate --endpoint wss://...`
 */
async function handlePairGenerate(params: {
  identity: ReturnType<typeof getIdentity>;
  store: TrustStore;
  endpoint: string;
  timeoutMs: number;
  capabilities: FederationCapability[];
  json: boolean;
}): Promise<void> {
  const manager = new PairingManager({
    identity: params.identity,
    trustStore: params.store,
  });

  const { code, data } = manager.generatePairingCode({
    endpoint: params.endpoint,
    expiresInMs: params.timeoutMs,
  });

  if (params.json) {
    console.log(
      JSON.stringify({
        code,
        endpoint: params.endpoint,
        publicKey: data.publicKey,
        instanceName: params.identity.name,
        expiresAt: data.expiresAt,
        expiresInMs: params.timeoutMs,
      }),
    );
    return;
  }

  const expiresMin = Math.round(params.timeoutMs / 60_000);

  console.log("");
  console.log(
    chalk.bold(`  Federation Pairing Code`) +
      chalk.dim(` (expires in ${expiresMin} minutes)`) +
      chalk.bold(":"),
  );
  console.log("");
  console.log(chalk.cyan.bold(`    ${code}`));
  console.log("");
  console.log(chalk.dim("  Share this code with the other OpenClaw instance owner."));
  console.log(chalk.dim("  They should run:"));
  console.log("");
  console.log(
    `    ${chalk.cyan("openclaw federation pair")} --code ${chalk.yellow(code.slice(0, 20) + "...")}`,
  );
  console.log("");
}

/**
 * Accept an OC- pairing code.
 * `openclaw federation pair --code OC-xxxx-... --endpoint wss://...`
 */
async function handlePairWithCode(params: {
  identity: ReturnType<typeof getIdentity>;
  store: TrustStore;
  code: string;
  endpoint?: string;
  capabilities: FederationCapability[];
  json: boolean;
}): Promise<void> {
  // Decode to show info before connecting
  const data = decodePairingCode(params.code);
  if (!data) {
    if (params.json) {
      console.log(JSON.stringify({ ok: false, error: "Invalid pairing code format" }));
    } else {
      console.error(chalk.red("\n  ❌ Invalid pairing code format."));
      console.error(chalk.gray("  Make sure you copied the entire OC-xxxx-... code.\n"));
    }
    process.exit(1);
    return;
  }

  if (Date.now() > data.expiresAt) {
    if (params.json) {
      console.log(JSON.stringify({ ok: false, error: "Pairing code has expired" }));
    } else {
      console.error(chalk.red("\n  ❌ This pairing code has expired."));
      console.error(chalk.gray("  Ask the other instance to generate a new code.\n"));
    }
    process.exit(1);
    return;
  }

  // Extract hostname from endpoint for display
  let peerHost = data.endpoint;
  try {
    peerHost = new URL(data.endpoint).hostname;
  } catch {
    /* use raw */
  }

  if (!params.json) {
    console.log("");
    console.log(
      `  Pairing with: ${chalk.bold(data.instanceName ?? "Unknown")} ${chalk.dim("(" + peerHost + ")")}`,
    );
  }

  const manager = new PairingManager({
    identity: params.identity,
    trustStore: params.store,
  });

  const ourEndpoint = params.endpoint ?? readFederationConfig().endpoint ?? "";

  const result = await manager.acceptPairingCode(params.code, ourEndpoint);

  if (!result.ok) {
    const errResult = result as { ok: false; error: string };
    if (params.json) {
      console.log(JSON.stringify({ ok: false, error: errResult.error }));
    } else {
      console.error(chalk.red(`  ✗ ${errResult.error}`));
      console.log("");
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
        endpoint: pairingResult.peerEndpoint,
      }),
    );
    return;
  }

  // Pretty output with step-by-step checkmarks
  console.log(chalk.green("  ✓ Challenge verified"));
  console.log(chalk.green("  ✓ Keys exchanged"));
  console.log(chalk.green("  ✓ Endpoints registered"));
  console.log(chalk.green("  ✓ Connection established"));
  console.log("");
  console.log(chalk.green.bold(`  Peer "${pairingResult.peerName}" added successfully.`));
  console.log(
    chalk.dim("  Run ") +
      chalk.cyan("openclaw federation peers") +
      chalk.dim(" to see all connected peers."),
  );
  console.log("");
}

// ─── Legacy Pairing Flow Handlers ───────────────────────────

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
          console.log(chalk.yellow("  📥 Incoming pairing request!"));
          console.log(
            `  From: ${chalk.bold(session.remoteIdentity.name)} (${chalk.cyan(formatPeerId(session.remoteIdentity.peerId))})`,
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
        console.log(chalk.dim(`  ℹ️  ${msg}`));
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
      console.log(chalk.dim("  On the other instance, run:"));
      console.log(
        `  $ ${chalk.cyan(`openclaw federation pair --code ${session.setupCode} --url ${url}`)}`,
      );
      console.log("");

      const qrData = generateQrPayload({
        setupCode: session.setupCode,
        publicKeyPem: params.identity.publicKeyPem,
        endpoint: `${url}/federation/pair`,
        instanceName: params.identity.name,
      });
      console.log(chalk.dim(`  QR data: ${qrData}`));
      console.log("");
    }

    // Wait for completion
    const result = await server.waitForCompletion();
    if (!result && !params.json) {
      console.log(chalk.yellow("  ⏰ Pairing session expired or was cancelled.\n"));
    }
  } catch (err) {
    console.error(chalk.red(`\n  ❌ ${err instanceof Error ? err.message : String(err)}\n`));
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
    console.error(chalk.red("\n  ❌ --url is required in client mode."));
    console.error(
      chalk.gray("  Usage: openclaw federation pair --code ABCDEF --url http://host:port\n"),
    );
    process.exit(1);
    return;
  }

  if (!params.json) {
    console.log(`\n  🔗 Connecting to ${chalk.cyan(params.serverUrl)}...`);
    console.log(`  📝 Using setup code: ${chalk.bold(params.setupCode)}\n`);
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
      console.error(chalk.red(`\n  ❌ Pairing failed: ${errMsg}\n`));
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
