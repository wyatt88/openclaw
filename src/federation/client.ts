/**
 * Federation Client — Phase 1: OpenAI API Bridge
 *
 * Communicates with peer OpenClaw instances via their standard
 * /v1/chat/completions HTTP endpoint.
 *
 * This is the lightest possible integration: no new protocol needed,
 * just standard HTTP + OpenAI-compatible JSON.
 */

import type {
  FederationChatResult,
  FederationConfig,
  FederationPeer,
  FederationPeerHealth,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 120_000; // 2 minutes
const HEALTH_CHECK_TIMEOUT_MS = 10_000;

/**
 * Send a chat message to a peer Gateway via /v1/chat/completions.
 */
export async function sendChatToPeer(params: {
  peer: FederationPeer;
  message: string;
  systemPrompt?: string;
  model?: string;
  stream?: boolean;
}): Promise<FederationChatResult> {
  const { peer, message, systemPrompt, model, stream } = params;
  const url = `${peer.url.replace(/\/$/, "")}/v1/chat/completions`;
  const timeoutMs = peer.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const startedAt = Date.now();

  const messages: Array<{ role: string; content: string }> = [];
  if (systemPrompt) {
    messages.push({ role: "system", content: systemPrompt });
  }
  messages.push({ role: "user", content: message });

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (peer.token) {
    headers["Authorization"] = `Bearer ${peer.token}`;
  }

  const body = JSON.stringify({
    model: model ?? "default",
    messages,
    stream: stream ?? false,
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers,
      body,
      signal: controller.signal,
    });

    if (!response.ok) {
      const errorBody = await response.text().catch(() => "");
      return {
        ok: false,
        peerId: peer.id,
        error: `HTTP ${response.status}: ${errorBody.slice(0, 500)}`,
        latencyMs: Date.now() - startedAt,
      };
    }

    const result = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
      model?: string;
      usage?: {
        prompt_tokens?: number;
        completion_tokens?: number;
        total_tokens?: number;
      };
    };

    const text = result.choices?.[0]?.message?.content ?? undefined;

    return {
      ok: true,
      peerId: peer.id,
      text,
      model: result.model ?? model,
      usage: result.usage,
      latencyMs: Date.now() - startedAt,
    };
  } catch (err) {
    const isAbort = err instanceof DOMException && err.name === "AbortError";
    return {
      ok: false,
      peerId: peer.id,
      error: isAbort
        ? `Timeout after ${timeoutMs}ms`
        : err instanceof Error
          ? err.message
          : String(err),
      latencyMs: Date.now() - startedAt,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Check health of a peer Gateway by hitting /health.
 */
export async function checkPeerHealth(peer: FederationPeer): Promise<FederationPeerHealth> {
  const url = `${peer.url.replace(/\/$/, "")}/health`;
  const startedAt = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), HEALTH_CHECK_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "GET",
      signal: controller.signal,
    });

    return {
      peerId: peer.id,
      peerName: peer.name,
      reachable: response.ok,
      latencyMs: Date.now() - startedAt,
      error: response.ok ? undefined : `HTTP ${response.status}`,
      checkedAt: Date.now(),
    };
  } catch (err) {
    return {
      peerId: peer.id,
      peerName: peer.name,
      reachable: false,
      latencyMs: Date.now() - startedAt,
      error: err instanceof Error ? err.message : String(err),
      checkedAt: Date.now(),
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Federation Registry — manages known peers and their state.
 */
export class FederationRegistry {
  private readonly peers: Map<string, FederationPeer> = new Map();
  private readonly healthCache: Map<string, FederationPeerHealth> = new Map();

  constructor(config?: FederationConfig) {
    if (config?.peers) {
      for (const peer of config.peers) {
        this.peers.set(peer.id, peer);
      }
    }
  }

  getPeer(id: string): FederationPeer | undefined {
    return this.peers.get(id);
  }

  listPeers(): FederationPeer[] {
    return Array.from(this.peers.values());
  }

  addPeer(peer: FederationPeer): void {
    this.peers.set(peer.id, peer);
  }

  removePeer(id: string): boolean {
    this.healthCache.delete(id);
    return this.peers.delete(id);
  }

  getHealth(peerId: string): FederationPeerHealth | undefined {
    return this.healthCache.get(peerId);
  }

  /**
   * Check health of all registered peers.
   */
  async checkAllHealth(): Promise<FederationPeerHealth[]> {
    const results = await Promise.all(
      this.listPeers().map((peer) => checkPeerHealth(peer)),
    );
    for (const result of results) {
      this.healthCache.set(result.peerId, result);
    }
    return results;
  }

  /**
   * Send a chat message to a specific peer.
   */
  async chat(params: {
    peerId: string;
    message: string;
    systemPrompt?: string;
    model?: string;
  }): Promise<FederationChatResult> {
    const peer = this.peers.get(params.peerId);
    if (!peer) {
      return {
        ok: false,
        peerId: params.peerId,
        error: `Unknown peer: ${params.peerId}`,
        latencyMs: 0,
      };
    }
    return sendChatToPeer({
      peer,
      message: params.message,
      systemPrompt: params.systemPrompt,
      model: params.model,
    });
  }

  /**
   * Broadcast a message to all peers and collect responses.
   */
  async broadcast(params: {
    message: string;
    systemPrompt?: string;
    model?: string;
  }): Promise<FederationChatResult[]> {
    return Promise.all(
      this.listPeers().map((peer) =>
        sendChatToPeer({
          peer,
          message: params.message,
          systemPrompt: params.systemPrompt,
          model: params.model,
        }),
      ),
    );
  }
}
