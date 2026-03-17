/**
 * Federation Web UI — HTTP API endpoints for federation management
 *
 * Provides REST-style API endpoints for a web dashboard:
 *   GET    /api/federation/status         — Federation status + peers overview
 *   GET    /api/federation/peers          — Detailed peers list
 *   POST   /api/federation/pair/generate  — Generate pairing code
 *   POST   /api/federation/pair/accept    — Accept a pairing code
 *   DELETE /api/federation/peers/:peerId  — Revoke trust for a peer
 *
 * All endpoints require Gateway auth token via `Authorization: Bearer <token>`.
 *
 * @module federation/web-ui
 */

import type http from "node:http";
import { prependHttpHandler } from "../gateway/server-http.js";
import type { FederationNode } from "./client.js";
import { formatPeerId, generateChallenge } from "./crypto.js";
import { encodePairingCode, decodePairingCode, type PairingCodeData } from "./pairing.js";
import type { FederationTransport } from "./transport.js";
import type { FederationCapability } from "./types.js";

// Re-export pairing code functions for consumers that import from web-ui
export { encodePairingCode, decodePairingCode } from "./pairing.js";

// ─── Types ──────────────────────────────────────────────────

/** Options for creating federation Web UI routes. */
export type WebUiOptions = {
  /** The FederationNode instance. */
  node: FederationNode;
  /** The FederationTransport instance. */
  transport: FederationTransport;
  /** Gateway auth token for request validation. */
  authToken: string;
  /** Default capabilities to grant on pairing. */
  defaultCapabilities?: FederationCapability[];
};

/** Route handler signature matching Express-like pattern. */
export type FederationApiRoute = {
  method: "GET" | "POST" | "DELETE";
  path: string;
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void>;
};

// ─── Helpers ────────────────────────────────────────────────

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function parseBody(req: http.IncomingMessage): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      try {
        const text = Buffer.concat(chunks).toString("utf8");
        resolve(text ? (JSON.parse(text) as Record<string, unknown>) : {});
      } catch (err) {
        reject(new Error(`Invalid JSON body: ${String(err)}`));
      }
    });
    req.on("error", reject);
  });
}

function validateAuth(req: http.IncomingMessage, expectedToken: string): boolean {
  const auth = req.headers.authorization;
  if (!auth) {
    return false;
  }
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match?.[1] === expectedToken;
}

/**
 * Extract the trailing path segment for parameterized routes.
 * e.g. "/api/federation/peers/abc123" → "abc123"
 */
function extractPathParam(url: string, prefix: string): string | null {
  if (!url.startsWith(prefix)) {
    return null;
  }
  const rest = url.slice(prefix.length);
  return rest.startsWith("/") ? rest.slice(1).split("?")[0] || null : null;
}

// ─── Route Creation ─────────────────────────────────────────

/**
 * Create all federation Web UI API routes.
 *
 * @returns An array of route definitions to register on the HTTP server.
 */
export function createFederationApiRoutes(opts: WebUiOptions): FederationApiRoute[] {
  const { node, transport } = opts;

  const routes: FederationApiRoute[] = [];

  // ── GET /api/federation/status ────────────────────────
  routes.push({
    method: "GET",
    path: "/api/federation/status",
    handler: async (_req, res) => {
      const status = node.getStatus();
      const connections = transport.getConnectionInfo();

      sendJson(res, 200, {
        ok: true,
        enabled: status.enabled,
        identity: {
          peerId: formatPeerId(status.identity.peerId),
          name: status.identity.name,
        },
        peers: status.peers.map((p) => ({
          peerId: p.peerId.startsWith("token:") ? p.peerId : formatPeerId(p.peerId),
          name: p.peerName,
          connected: p.connected,
          trust: p.trust,
          latencyMs: p.latencyMs,
          lastSeenAt: p.lastSeenAt ? new Date(p.lastSeenAt).toISOString() : null,
          endpoint: p.endpoint,
          capabilities: p.capabilities,
          tokenAuth: p.tokenAuth ?? false,
        })),
        transport: {
          activeConnections: transport.activeConnectionCount,
          connections: connections.map((c) => ({
            peerId: formatPeerId(c.peerId),
            peerName: c.peerName,
            direction: c.outbound ? "outbound" : "inbound",
          })),
        },
        totalConnected: status.totalConnected,
        totalTrusted: status.totalTrusted,
      });
    },
  });

  // ── GET /api/federation/peers ─────────────────────────
  routes.push({
    method: "GET",
    path: "/api/federation/peers",
    handler: async (_req, res) => {
      // Merge trust store peers with live transport connection state
      const connectionInfo = transport.getConnectionInfo();
      const connectionMap = new Map(connectionInfo.map((c) => [c.peerId, c]));

      const trustStorePeers = node.trustStore.listPeers().map((peer) => {
        const conn = connectionMap.get(peer.identity.peerId);
        const isConnected = conn?.phase === "Ready";
        return {
          peerId: formatPeerId(peer.identity.peerId),
          fullPeerId: peer.identity.peerId,
          name: peer.identity.name,
          connected: isConnected,
          trust: peer.trust,
          endpoint: peer.endpoint.wsUrl ?? peer.endpoint.httpUrl ?? peer.endpoint.tailnetHostname,
          capabilities: peer.grantedCapabilities.capabilities,
          lastSeenAt: peer.lastSeenAt ? new Date(peer.lastSeenAt).toISOString() : null,
          addedAt: new Date(peer.addedAt).toISOString(),
          tokenAuth: false,
        };
      });

      // Include simple peers
      const simplePeers = node.listSimplePeers().map(({ peerId, peer }) => ({
        peerId,
        fullPeerId: peerId,
        name: peer.name,
        connected: false, // Managed by transport layer
        trust: "direct" as const,
        endpoint: peer.endpoint,
        capabilities: peer.capabilities ?? ["chat"],
        lastSeenAt: null,
        addedAt: null,
        tokenAuth: true,
      }));

      const allPeers = [...trustStorePeers, ...simplePeers];
      const connectedCount = allPeers.filter((p) => p.connected).length;

      sendJson(res, 200, {
        ok: true,
        thisInstance: {
          peerId: formatPeerId(node.identity.peerId),
          name: node.identity.name,
        },
        peers: allPeers,
        summary: {
          total: allPeers.length,
          connected: connectedCount,
          trusted: trustStorePeers.length,
        },
      });
    },
  });

  // ── POST /api/federation/pair/generate ────────────────
  routes.push({
    method: "POST",
    path: "/api/federation/pair/generate",
    handler: async (req, res) => {
      let body: Record<string, unknown>;
      try {
        body = await parseBody(req);
      } catch {
        sendJson(res, 400, { ok: false, error: "Invalid JSON body" });
        return;
      }

      const endpoint = (body.endpoint as string) ?? "";

      const challenge = generateChallenge();
      const expiresAt = Date.now() + 60_000; // 60s TTL

      const codeData: PairingCodeData = {
        publicKey: node.identity.publicKeyPem,
        endpoint: typeof endpoint === "string" ? endpoint : "",
        challenge,
        expiresAt,
        instanceName: node.identity.name,
      };

      const code = encodePairingCode(codeData);

      sendJson(res, 200, {
        ok: true,
        code,
        expiresAt: new Date(expiresAt).toISOString(),
        instanceName: node.identity.name,
        peerId: formatPeerId(node.identity.peerId),
      });
    },
  });

  // ── POST /api/federation/pair/accept ──────────────────
  routes.push({
    method: "POST",
    path: "/api/federation/pair/accept",
    handler: async (req, res) => {
      let body: Record<string, unknown>;
      try {
        body = await parseBody(req);
      } catch {
        sendJson(res, 400, { ok: false, error: "Invalid JSON body" });
        return;
      }

      const code = body.code as string | undefined;
      const localEndpoint = body.endpoint as string | undefined;

      if (!code) {
        sendJson(res, 400, { ok: false, error: "Missing required field: code" });
        return;
      }

      const decoded = decodePairingCode(code);
      if (!decoded) {
        sendJson(res, 400, { ok: false, error: "Invalid pairing code format" });
        return;
      }

      // Check expiry
      if (Date.now() > decoded.expiresAt) {
        sendJson(res, 400, { ok: false, error: "Pairing code has expired" });
        return;
      }

      sendJson(res, 200, {
        ok: true,
        peerPublicKey: decoded.publicKey.slice(0, 40) + "…",
        peerEndpoint: decoded.endpoint,
        localEndpoint: localEndpoint ?? null,
        note: "Pairing data decoded. Full key exchange requires transport-layer handshake.",
      });
    },
  });

  // ── DELETE /api/federation/peers/:peerId ──────────────
  routes.push({
    method: "DELETE",
    path: "/api/federation/peers",
    handler: async (req, res) => {
      const url = req.url ?? "";
      const peerId = extractPathParam(url, "/api/federation/peers");

      if (!peerId) {
        sendJson(res, 400, { ok: false, error: "Missing peerId in URL path" });
        return;
      }

      // Check simple peers first
      if (peerId.startsWith("token:")) {
        const simplePeer = node.simplePeers.get(peerId);
        if (simplePeer) {
          node.simplePeers.delete(peerId);
          node.listSimplePeers(); // Force re-index
          sendJson(res, 200, {
            ok: true,
            removed: true,
            peer: { peerId, name: simplePeer.name, tokenAuth: true },
          });
          return;
        }
      }

      // Search trust store
      const allPeers = node.trustStore.listPeers();
      const match = allPeers.find(
        (p) => p.identity.peerId === peerId || formatPeerId(p.identity.peerId) === peerId,
      );

      if (!match) {
        sendJson(res, 404, { ok: false, error: `Peer not found: ${peerId}` });
        return;
      }

      const fullPeerId = match.identity.peerId;
      node.disconnectPeer(fullPeerId);
      const removed = node.trustStore.removePeer(fullPeerId);

      sendJson(res, 200, {
        ok: true,
        removed,
        peer: {
          peerId: formatPeerId(fullPeerId),
          name: match.identity.name,
        },
      });
    },
  });

  return routes;
}

/**
 * Register federation API routes on an HTTP server as a middleware.
 *
 * Attaches a `request` listener that intercepts `/api/federation/*` paths
 * and delegates to the appropriate route handler.
 */
export function registerFederationApiMiddleware(server: http.Server, opts: WebUiOptions): void {
  const routes = createFederationApiRoutes(opts);

  // Use prependHttpHandler to avoid Node.js multiple request listener race
  // that causes "Cannot set headers after they are sent to the client" crashes.
  prependHttpHandler(async (req, res) => {
    const url = req.url ?? "";
    const method = req.method ?? "GET";

    // Only handle /api/federation/* paths
    if (!url.startsWith("/api/federation/")) {
      return false;
    }

    // Auth check
    if (!validateAuth(req, opts.authToken)) {
      sendJson(res, 401, { ok: false, error: "Unauthorized — provide Bearer token" });
      return true;
    }

    // Find matching route
    for (const route of routes) {
      if (method !== route.method) {
        continue;
      }

      // Exact match or prefix match (for parameterized routes like DELETE /peers/:id)
      if (
        url === route.path ||
        url.startsWith(route.path + "/") ||
        url.startsWith(route.path + "?")
      ) {
        try {
          await route.handler(req, res);
        } catch (err) {
          sendJson(res, 500, { ok: false, error: `Internal error: ${String(err)}` });
        }
        return true;
      }
    }

    // No route matched under /api/federation/
    sendJson(res, 404, { ok: false, error: `Not found: ${method} ${url}` });
    return true;
  });
}

/**
 * Convenience wrapper for registering federation Web UI routes.
 * Used by `gateway-integration.ts` during initialization.
 *
 * @param params.server - HTTP server to attach routes to
 * @param params.federationNode - FederationNode instance
 * @param params.config - Federation config (unused, reserved for future use)
 * @param params.gatewayToken - Auth token for API access
 */
export function registerFederationWebRoutes(params: {
  server: http.Server;
  federationNode: FederationNode;
  transport: FederationTransport;
  config: unknown;
  gatewayToken: string;
}): void {
  registerFederationApiMiddleware(params.server, {
    node: params.federationNode,
    transport: params.transport,
    authToken: params.gatewayToken,
  });
}
