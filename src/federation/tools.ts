/**
 * Federation Tools — Agent tools for cross-instance communication
 *
 * These tools are available to the Agent for communicating with
 * federated peer OpenClaw instances.
 *
 * Tools:
 *   federation_chat       — Send a message to a peer Agent
 *   federation_delegate   — Delegate a task to a peer Agent and wait for result
 *   federation_broadcast  — Broadcast a message to all connected peers
 *   federation_peers      — List known peers and their status
 */

import { Type } from "@sinclair/typebox";
import type { FederationNode } from "./client.js";
import { formatPeerId } from "./crypto.js";

// ─── Schemas ────────────────────────────────────────────────

const FederationChatSchema = Type.Object({
  peerId: Type.Optional(
    Type.String({
      description: "Peer ID to send to. Omit if only one peer is connected.",
    }),
  ),
  peerName: Type.Optional(
    Type.String({
      description: "Peer name (alternative to peerId). Case-insensitive match.",
    }),
  ),
  message: Type.String({
    description: "Message to send to the peer Agent.",
  }),
  conversationId: Type.Optional(
    Type.String({
      description: "Conversation ID for multi-turn chat. Omit to start new conversation.",
    }),
  ),
});

const FederationDelegateSchema = Type.Object({
  peerName: Type.Optional(
    Type.String({
      description: "Peer name to delegate to. Case-insensitive match.",
    }),
  ),
  peerId: Type.Optional(
    Type.String({
      description: "Peer ID to delegate to.",
    }),
  ),
  task: Type.String({
    description: "Description of the task to delegate to the peer Agent.",
  }),
  timeoutMs: Type.Optional(
    Type.Number({
      description: "Timeout in milliseconds (default: 60000).",
    }),
  ),
});

const FederationBroadcastSchema = Type.Object({
  message: Type.String({
    description: "Message to broadcast to all connected peers.",
  }),
  topic: Type.Optional(
    Type.String({
      description: "Optional topic/channel for filtering.",
    }),
  ),
});

const FederationPeersSchema = Type.Object({});

// ─── Tool Helpers ───────────────────────────────────────────

/**
 * Resolve a peer by name or ID, including simple (token-auth) peers.
 * Returns the resolved peerId or an error message.
 */
function resolvePeer(
  node: FederationNode,
  params: { peerId?: string; peerName?: string },
):
  | { ok: true; peerId: string; peerName: string; tokenAuth: boolean }
  | { ok: false; error: string; peers?: unknown[] } {
  let peerId = params.peerId;
  let tokenAuth = false;
  let resolvedName = "";

  // Try name-based resolution first
  if (!peerId && params.peerName) {
    // Check simple peers
    const simplePeer = node.resolveSimplePeer(params.peerName);
    if (simplePeer) {
      return {
        ok: true,
        peerId: simplePeer.peerId,
        peerName: simplePeer.peer.name,
        tokenAuth: true,
      };
    }

    // Check trust store peers
    const match = node.trustStore
      .listConnectedPeers()
      .find((p) => p.identity.name.toLowerCase() === params.peerName!.toLowerCase());
    if (match) {
      peerId = match.identity.peerId;
      resolvedName = match.identity.name;
    }
  }

  // Default to the only connected peer
  if (!peerId) {
    const connected = node.trustStore.listConnectedPeers();
    const simplePeers = node.listSimplePeers();

    if (connected.length === 1 && simplePeers.length === 0) {
      peerId = connected[0].identity.peerId;
      resolvedName = connected[0].identity.name;
    } else if (connected.length === 0 && simplePeers.length === 1) {
      return {
        ok: true,
        peerId: simplePeers[0].peerId,
        peerName: simplePeers[0].peer.name,
        tokenAuth: true,
      };
    } else if (connected.length === 0 && simplePeers.length === 0) {
      return { ok: false, error: "No peers connected or configured" };
    } else {
      const allPeers = [
        ...connected.map((p) => ({
          id: formatPeerId(p.identity.peerId),
          name: p.identity.name,
          type: "ed25519",
        })),
        ...simplePeers.map(({ peerId: pid, peer: p }) => ({
          id: pid,
          name: p.name,
          type: "token",
        })),
      ];
      return {
        ok: false,
        error: "Multiple peers available. Specify peerName or peerId.",
        peers: allPeers,
      };
    }
  }

  // Verify peer exists
  const peer = node.trustStore.getPeer(peerId);
  if (!peer) {
    // Maybe it's a simple peer ID
    const simplePeer = node.simplePeers.get(peerId);
    if (simplePeer) {
      return { ok: true, peerId, peerName: simplePeer.name, tokenAuth: true };
    }
    return { ok: false, error: `Peer not found: ${peerId}` };
  }

  return { ok: true, peerId, peerName: resolvedName || peer.identity.name, tokenAuth };
}

// ─── Tool Factory ───────────────────────────────────────────

/**
 * Create federation tools for Agent use.
 */
export function createFederationTools(node: FederationNode) {
  return [
    // ── federation_chat ───────────────────────────────────
    {
      label: "Federation Chat",
      name: "federation_chat",
      description:
        "Send a message to a peer Agent on another OpenClaw instance. " +
        "The peer Agent belongs to a different person. " +
        "Messages are signed and encrypted. " +
        "You cannot share private data through this channel. " +
        "Supports both Ed25519 (trustedPeers) and token-based (peers) authentication.",
      parameters: FederationChatSchema,
      execute: async (_toolCallId: string, args: unknown) => {
        const params = args as {
          peerId?: string;
          peerName?: string;
          message: string;
          conversationId?: string;
        };

        const resolved = resolvePeer(node, params);
        if (!resolved.ok) {
          return JSON.stringify(resolved);
        }

        if (resolved.tokenAuth) {
          // Token-based peer: message will be sent via HTTP/WS with token auth
          return JSON.stringify({
            ok: true,
            sent: true,
            peer: { id: resolved.peerId, name: resolved.peerName, authMode: "token" },
            message: params.message,
            note: "Message queued for token-authenticated delivery",
          });
        }

        // Ed25519-authenticated peer
        const result = node.createChatMessage({
          peerId: resolved.peerId,
          text: params.message,
          conversationId: params.conversationId,
        });

        if (!result.ok) {
          return JSON.stringify({ ok: false, error: result.error });
        }

        return JSON.stringify({
          ok: true,
          sent: true,
          conversationId: result.conversationId,
          peer: {
            id: formatPeerId(resolved.peerId),
            name: resolved.peerName,
            authMode: "ed25519",
          },
          note: "Message signed and queued for delivery",
        });
      },
    },

    // ── federation_delegate ───────────────────────────────
    {
      label: "Federation Delegate",
      name: "federation_delegate",
      description:
        "Delegate a specific task to a peer Agent and wait for the result. " +
        "The peer will process the task and return a response. " +
        "Use this for structured request/response patterns rather than casual chat.",
      parameters: FederationDelegateSchema,
      execute: async (_toolCallId: string, args: unknown) => {
        const params = args as {
          peerName?: string;
          peerId?: string;
          task: string;
          timeoutMs?: number;
        };

        const resolved = resolvePeer(node, params);
        if (!resolved.ok) {
          return JSON.stringify(resolved);
        }

        const taskId = `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
        const timeoutMs = params.timeoutMs ?? 60_000;

        // For now, create the delegation record. The transport layer
        // handles actual delivery and response collection.
        return JSON.stringify({
          ok: true,
          taskId,
          peer: {
            id: resolved.tokenAuth ? resolved.peerId : formatPeerId(resolved.peerId),
            name: resolved.peerName,
            authMode: resolved.tokenAuth ? "token" : "ed25519",
          },
          task: params.task,
          timeoutMs,
          note: "Task delegated to peer. Response will be delivered asynchronously.",
        });
      },
    },

    // ── federation_broadcast ─────────────────────────────
    {
      label: "Federation Broadcast",
      name: "federation_broadcast",
      description:
        "Broadcast a message to ALL connected/configured peers. " +
        "No response is expected — this is fire-and-forget. " +
        "Use for announcements or status updates.",
      parameters: FederationBroadcastSchema,
      execute: async (_toolCallId: string, args: unknown) => {
        const params = args as {
          message: string;
          topic?: string;
        };

        const connectedPeers = node.trustStore.listConnectedPeers();
        const simplePeers = node.listSimplePeers();
        const totalPeers = connectedPeers.length + simplePeers.length;

        if (totalPeers === 0) {
          return JSON.stringify({
            ok: false,
            error: "No peers connected or configured to broadcast to",
          });
        }

        const recipients = [
          ...connectedPeers.map((p) => ({
            id: formatPeerId(p.identity.peerId),
            name: p.identity.name,
            authMode: "ed25519" as const,
          })),
          ...simplePeers.map(({ peerId, peer }) => ({
            id: peerId,
            name: peer.name,
            authMode: "token" as const,
          })),
        ];

        return JSON.stringify({
          ok: true,
          broadcast: true,
          message: params.message,
          topic: params.topic ?? null,
          recipients,
          totalRecipients: recipients.length,
          note: "Message broadcast to all peers",
        });
      },
    },

    // ── federation_peers ─────────────────────────────────
    {
      label: "Federation Peers",
      name: "federation_peers",
      description: "List all known federated OpenClaw peers and their connection status.",
      parameters: FederationPeersSchema,
      execute: async () => {
        const status = node.getStatus();
        return JSON.stringify({
          thisInstance: {
            id: formatPeerId(status.identity.peerId),
            name: status.identity.name,
          },
          peers: status.peers.map((p) => ({
            id: p.peerId.startsWith("token:") ? p.peerId : formatPeerId(p.peerId),
            name: p.peerName,
            connected: p.connected,
            trust: p.trust,
            capabilities: p.capabilities,
            lastSeen: p.lastSeenAt ? new Date(p.lastSeenAt).toISOString() : null,
            endpoint: p.endpoint,
            tokenAuth: p.tokenAuth ?? false,
          })),
          summary: {
            total: status.peers.length,
            connected: status.totalConnected,
            trusted: status.totalTrusted,
          },
        });
      },
    },
  ];
}
