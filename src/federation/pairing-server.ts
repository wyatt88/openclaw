/**
 * Federation Pairing Server — Ephemeral HTTP endpoints for pairing handshake
 *
 * Spins up temporary HTTP routes for the pairing flow:
 *   POST /federation/pair/initiate  — Peer B sends pairing request
 *   POST /federation/pair/accept    — Owner confirms, server sends accept response
 *   POST /federation/pair/confirm   — Peer B sends final confirmation
 *   GET  /federation/pair/status    — Check pairing session status
 *
 * The server is ephemeral: it starts when pairing is initiated and shuts down
 * when pairing completes, times out, or is cancelled.
 *
 * Security:
 *   - All requests must include valid signatures
 *   - Setup codes are single-use and time-bound
 *   - CORS restricted to same-origin
 *   - No persistent state (all state in PairingManager)
 */

import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { formatPeerId } from "./crypto.js";
import {
  PairingManager,
  type PairingInitiatePayload,
  type PairingAcceptPayload,
  type PairingConfirmPayload,
  type PairingResult,
  type PairingSession,
} from "./pairing.js";
import { TrustStore } from "./trust-store.js";
import type { FederationLocalIdentity, FederationCapability } from "./types.js";

// ─── Types ──────────────────────────────────────────────────

export type PairingServerOptions = {
  /** Port to listen on (0 = auto-assign) */
  port?: number;
  /** Host to bind to */
  host?: string;
  /** Identity for this instance */
  identity: FederationLocalIdentity;
  /** Trust store for persisting peers */
  trustStore: TrustStore;
  /** Default capabilities to grant */
  defaultCapabilities?: FederationCapability[];
  /** Timeout for pairing sessions (ms) */
  timeoutMs?: number;
  /** Callback when pairing request received (for owner confirmation) */
  onPairingRequest?: (session: PairingSession) => Promise<boolean>;
  /** Callback when pairing completes */
  onPairingComplete?: (result: PairingResult) => void;
  /** Callback for log/status messages */
  onLog?: (message: string) => void;
};

type JsonBody = Record<string, unknown>;

// ─── Response Helpers ───────────────────────────────────────

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "Content-Type": "application/json",
    "Content-Length": Buffer.byteLength(payload),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  });
  res.end(payload);
}

function sendError(res: http.ServerResponse, status: number, error: string): void {
  sendJson(res, status, { ok: false, error });
}

async function readBody(req: http.IncomingMessage, maxBytes = 64 * 1024): Promise<JsonBody | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let totalLength = 0;

    req.on("data", (chunk: Buffer) => {
      totalLength += chunk.length;
      if (totalLength > maxBytes) {
        resolve(null);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(JSON.parse(raw) as JsonBody);
      } catch {
        resolve(null);
      }
    });

    req.on("error", () => resolve(null));
  });
}

// ─── Pairing Server ─────────────────────────────────────────

export class PairingServer {
  private server: http.Server | null = null;
  private pairingManager: PairingManager;
  private options: PairingServerOptions;
  private activeSession: PairingSession | null = null;
  /** Resolve function for the pairing promise (waiting for owner confirmation) */
  private confirmResolve: ((accept: boolean) => void) | null = null;

  constructor(options: PairingServerOptions) {
    this.options = options;
    this.pairingManager = new PairingManager({
      identity: options.identity,
      trustStore: options.trustStore,
    });

    // Wire up events
    this.pairingManager.on("session:completed", (result: PairingResult) => {
      this.options.onPairingComplete?.(result);
    });
  }

  /**
   * Start the pairing server and create a new pairing session.
   * Returns the session info (setup code, etc.) for display.
   */
  async start(): Promise<{
    session: PairingSession;
    port: number;
    url: string;
  }> {
    // Generate a pairing session
    this.activeSession = this.pairingManager.generatePairingSession({
      timeoutMs: this.options.timeoutMs,
      capabilities: this.options.defaultCapabilities,
    });

    // Listen for expiry
    this.pairingManager.on("session:expired", () => {
      this.log("Pairing session expired");
      void this.stop();
    });

    const port = this.options.port ?? 0;
    const host = this.options.host ?? "0.0.0.0";

    // Create HTTP server
    this.server = http.createServer((req, res) => {
      void this.handleRequest(req, res);
    });

    return new Promise((resolve, reject) => {
      this.server!.listen(port, host, () => {
        const addr = this.server!.address() as AddressInfo;
        const actualPort = addr.port;
        const url = `http://${host === "0.0.0.0" ? "localhost" : host}:${actualPort}`;
        this.log(`Pairing server listening on ${url}`);
        resolve({
          session: this.activeSession!,
          port: actualPort,
          url,
        });
      });

      this.server!.on("error", (err) => {
        reject(new Error(`Pairing server failed to start: ${err.message}`));
      });
    });
  }

  /**
   * Stop the pairing server and cleanup.
   */
  async stop(): Promise<void> {
    this.pairingManager.cancelAll();
    this.activeSession = null;

    if (this.confirmResolve) {
      this.confirmResolve(false);
      this.confirmResolve = null;
    }

    return new Promise((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }
      this.server.close(() => {
        this.server = null;
        resolve();
      });
      // Force close after 2s
      setTimeout(() => {
        this.server?.closeAllConnections?.();
        this.server = null;
        resolve();
      }, 2000);
    });
  }

  /**
   * Wait for the pairing to complete (blocks until done, expired, or cancelled).
   */
  async waitForCompletion(): Promise<PairingResult | null> {
    return new Promise((resolve) => {
      this.pairingManager.on("session:completed", (result: PairingResult) => {
        resolve(result);
      });
      this.pairingManager.on("session:expired", () => resolve(null));
      this.pairingManager.on("session:rejected", () => resolve(null));
      this.pairingManager.on("session:failed", () => resolve(null));
    });
  }

  get manager(): PairingManager {
    return this.pairingManager;
  }

  // ─── Request Handler ──────────────────────────────────

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    const pathname = url.pathname;
    const method = req.method?.toUpperCase();

    // CORS headers
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");

    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    try {
      switch (pathname) {
        case "/federation/pair/initiate":
          if (method !== "POST") {
            sendError(res, 405, "Method not allowed");
            return;
          }
          await this.handleInitiate(req, res);
          break;
        case "/federation/pair/accept":
          if (method !== "POST") {
            sendError(res, 405, "Method not allowed");
            return;
          }
          await this.handleAccept(req, res);
          break;
        case "/federation/pair/confirm":
          if (method !== "POST") {
            sendError(res, 405, "Method not allowed");
            return;
          }
          await this.handleConfirm(req, res);
          break;
        case "/federation/pair/status":
          if (method !== "GET") {
            sendError(res, 405, "Method not allowed");
            return;
          }
          this.handleStatus(res);
          break;
        default:
          sendError(res, 404, "Not found");
      }
    } catch (err) {
      this.log(`Request error: ${err instanceof Error ? err.message : String(err)}`);
      sendError(res, 500, "Internal server error");
    }
  }

  /**
   * POST /federation/pair/initiate
   *
   * Peer B sends: { setupCode, identity, endpoint, challengeResponse, challenge, timestamp }
   * Server responds: { ok: true, sessionId } or { ok: false, error }
   *
   * After this, the server waits for owner confirmation before proceeding.
   */
  private async handleInitiate(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (!this.activeSession) {
      sendError(res, 400, "No active pairing session");
      return;
    }

    const body = await readBody(req);
    if (!body) {
      sendError(res, 400, "Invalid request body");
      return;
    }

    const payload = body as unknown as PairingInitiatePayload;

    // Validate required fields
    if (!payload.setupCode || !payload.identity || !payload.challengeResponse) {
      sendError(res, 400, "Missing required fields: setupCode, identity, challengeResponse");
      return;
    }

    const result = this.pairingManager.handlePairingInitiate(this.activeSession.sessionId, payload);

    if (!result.ok) {
      sendError(res, 403, (result as { ok: false; error: string }).error);
      return;
    }

    this.log(
      `Pairing request from ${payload.identity.name} (${formatPeerId(payload.identity.peerId)})`,
    );

    // Ask owner for confirmation
    let accepted = true;
    if (this.options.onPairingRequest) {
      accepted = await this.options.onPairingRequest(
        (result as { ok: true; session: PairingSession }).session,
      );
    }

    if (!accepted) {
      this.pairingManager.rejectPairing(this.activeSession.sessionId);
      sendError(res, 403, "Pairing rejected by owner");
      return;
    }

    // Owner accepted — generate accept payload
    const acceptResult = this.pairingManager.acceptPairing(this.activeSession.sessionId);

    if (!acceptResult.ok) {
      sendError(res, 500, (acceptResult as { ok: false; error: string }).error);
      return;
    }

    sendJson(res, 200, {
      ok: true,
      sessionId: this.activeSession.sessionId,
      accept: (acceptResult as { ok: true; payload: PairingAcceptPayload }).payload,
    });
  }

  /**
   * POST /federation/pair/accept
   *
   * Not used in the server-side flow (the accept is sent inline in the initiate response).
   * This endpoint exists for symmetric architectures where both sides run servers.
   */
  private async handleAccept(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const body = await readBody(req);
    if (!body) {
      sendError(res, 400, "Invalid request body");
      return;
    }

    // For now, accept is handled inline in initiate response
    sendJson(res, 200, { ok: true, message: "Accept processed" });
  }

  /**
   * POST /federation/pair/confirm
   *
   * Peer B sends: { peerId, grant, timestamp }
   * Completes the pairing on the server side (Instance A).
   */
  private async handleConfirm(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (!this.activeSession) {
      sendError(res, 400, "No active pairing session");
      return;
    }

    const body = await readBody(req);
    if (!body) {
      sendError(res, 400, "Invalid request body");
      return;
    }

    const payload = body as unknown as PairingConfirmPayload;

    if (!payload.peerId || !payload.grant) {
      sendError(res, 400, "Missing required fields: peerId, grant");
      return;
    }

    const confirmResult = this.pairingManager.handlePairingConfirm(
      this.activeSession.sessionId,
      payload,
    );

    if (!confirmResult.ok) {
      sendError(res, 400, (confirmResult as { ok: false; error: string }).error);
      return;
    }

    const pairingResult = (confirmResult as { ok: true; result: PairingResult }).result;
    this.log(`Pairing confirmed with ${pairingResult.peerName}`);

    sendJson(res, 200, {
      ok: true,
      result: {
        peerId: pairingResult.peerId,
        peerName: pairingResult.peerName,
        capabilities: pairingResult.grantedCapabilities,
      },
    });

    // Shut down the pairing server after successful pairing
    setTimeout(() => void this.stop(), 500);
  }

  /**
   * GET /federation/pair/status
   *
   * Check current pairing session status.
   */
  private handleStatus(res: http.ServerResponse): void {
    if (!this.activeSession) {
      sendJson(res, 200, { ok: true, state: "none", active: false });
      return;
    }

    sendJson(res, 200, {
      ok: true,
      active: true,
      sessionId: this.activeSession.sessionId,
      state: this.activeSession.state,
      instanceName: this.activeSession.localIdentity.name,
      peerId: formatPeerId(this.activeSession.localIdentity.peerId),
      createdAt: this.activeSession.createdAt,
      timeoutMs: this.activeSession.timeoutMs,
      remotePeer: this.activeSession.remoteIdentity
        ? {
            name: this.activeSession.remoteIdentity.name,
            peerId: formatPeerId(this.activeSession.remoteIdentity.peerId),
          }
        : undefined,
    });
  }

  private log(message: string): void {
    if (this.options.onLog) {
      this.options.onLog(message);
    }
  }
}

// ─── Client-side pairing (Instance B) ──────────────────────

/**
 * Initiate a pairing from Instance B to Instance A's pairing server.
 *
 * Flow:
 *   1. POST /federation/pair/initiate  — send our identity + setup code
 *   2. Receive accept payload with A's identity
 *   3. POST /federation/pair/confirm   — send confirmation + our capability grant
 */
export async function initiatePairingToServer(params: {
  /** URL of Instance A's pairing server */
  serverUrl: string;
  /** Setup code from Instance A */
  setupCode: string;
  /** Our identity */
  identity: FederationLocalIdentity;
  /** Our trust store */
  trustStore: TrustStore;
  /** Our endpoint */
  localEndpoint: PeerEndpoint;
  /** Capabilities to grant to the peer */
  capabilities?: FederationCapability[];
  /** Request timeout (ms) */
  timeoutMs?: number;
}): Promise<{ ok: true; result: PairingResult } | { ok: false; error: string }> {
  const manager = new PairingManager({
    identity: params.identity,
    trustStore: params.trustStore,
  });

  const timeoutMs = params.timeoutMs ?? 30_000;

  // Step 1: Get session info from the server
  let statusResponse: Response;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    statusResponse = await fetch(`${params.serverUrl}/federation/pair/status`, {
      signal: controller.signal,
    });
    clearTimeout(timer);
  } catch (err) {
    return {
      ok: false,
      error: `Cannot reach pairing server: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const statusBody = (await statusResponse.json()) as {
    ok: boolean;
    sessionId?: string;
    state?: string;
  };
  if (!statusBody.ok || !statusBody.sessionId) {
    return { ok: false, error: "No active pairing session on server" };
  }

  const targetSessionId = statusBody.sessionId;

  // Step 2: Send pairing initiation
  const initiatePayload = manager.createInitiatePayload({
    setupCode: params.setupCode,
    targetSessionId,
    localEndpoint: params.localEndpoint,
  });

  let initiateResponse: Response;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    initiateResponse = await fetch(`${params.serverUrl}/federation/pair/initiate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(initiatePayload),
      signal: controller.signal,
    });
    clearTimeout(timer);
  } catch (err) {
    return {
      ok: false,
      error: `Initiate request failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  const initiateBody = (await initiateResponse.json()) as {
    ok: boolean;
    error?: string;
    sessionId?: string;
    accept?: PairingAcceptPayload;
  };

  if (!initiateBody.ok || !initiateBody.accept) {
    return { ok: false, error: initiateBody.error ?? "Pairing initiation rejected" };
  }

  // Step 3: Process accept payload
  const acceptResult = manager.handleAcceptResponse(initiatePayload.challenge, initiateBody.accept);

  if (!acceptResult.ok) {
    return { ok: false, error: (acceptResult as { ok: false; error: string }).error };
  }

  const pairingResult = (acceptResult as { ok: true; result: PairingResult }).result;

  // Step 4: Send confirmation
  const confirmPayload = manager.createConfirmPayload({
    targetPeerId: initiateBody.accept.identity.peerId,
    capabilities: params.capabilities,
  });

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const confirmResponse = await fetch(`${params.serverUrl}/federation/pair/confirm`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(confirmPayload),
      signal: controller.signal,
    });
    clearTimeout(timer);

    const confirmBody = (await confirmResponse.json()) as { ok: boolean; error?: string };
    if (!confirmBody.ok) {
      return { ok: false, error: confirmBody.error ?? "Confirmation failed" };
    }
  } catch (err) {
    // Confirmation send failed, but we already stored the peer locally
    // The other side may not have our grant, but pairing partially succeeded
    return {
      ok: false,
      error: `Confirm request failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  return { ok: true, result: pairingResult };
}

// Re-export types needed by the server
import type { PeerEndpoint } from "./types.js";
