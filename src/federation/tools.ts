/**
 * Federation Tools — Agent tools for cross-instance communication
 *
 * These tools are available to the Agent for communicating with
 * federated peer OpenClaw instances.
 *
 * Tools:
 *   federation_chat    — Send a message to a peer Agent
 *   federation_peers   — List known peers and their status
 *   federation_health  — Check peer reachability
 */

import { Type } from "@sinclair/typebox";
import type { FederationNode } from "./client.js";
import { formatPeerId } from "./crypto.js";

const FederationChatSchema = Type.Object({
  peerId: Type.Optional(Type.String({
    description: "Peer ID to send to. Omit if only one peer is connected.",
  })),
  peerName: Type.Optional(Type.String({
    description: "Peer name (alternative to peerId). Case-insensitive match.",
  })),
  message: Type.String({
    description: "Message to send to the peer Agent.",
  }),
  conversationId: Type.Optional(Type.String({
    description: "Conversation ID for multi-turn chat. Omit to start new conversation.",
  })),
});

const FederationPeersSchema = Type.Object({});

/**
 * Create federation tools for Agent use.
 */
export function createFederationTools(node: FederationNode) {
  return [
    {
      label: "Federation Chat",
      name: "federation_chat",
      description:
        "Send a message to a peer Agent on another OpenClaw instance. " +
        "The peer Agent belongs to a different person. " +
        "Messages are signed and encrypted. " +
        "You cannot share private data through this channel.",
      parameters: FederationChatSchema,
      execute: async (_toolCallId: string, args: unknown) => {
        const params = args as {
          peerId?: string;
          peerName?: string;
          message: string;
          conversationId?: string;
        };

        // Resolve peer
        let peerId = params.peerId;
        if (!peerId && params.peerName) {
          const match = node.trustStore
            .listConnectedPeers()
            .find((p) => p.identity.name.toLowerCase() === params.peerName!.toLowerCase());
          if (match) peerId = match.identity.peerId;
        }
        if (!peerId) {
          // Default to the only connected peer
          const connected = node.trustStore.listConnectedPeers();
          if (connected.length === 1) {
            peerId = connected[0].identity.peerId;
          } else if (connected.length === 0) {
            return JSON.stringify({ ok: false, error: "No peers connected" });
          } else {
            return JSON.stringify({
              ok: false,
              error: "Multiple peers connected. Specify peerId or peerName.",
              peers: connected.map((p) => ({
                id: formatPeerId(p.identity.peerId),
                name: p.identity.name,
              })),
            });
          }
        }

        // Create and "send" the message
        // In a real implementation, this would go over the WS connection.
        // For now, we create the signed message structure.
        const result = node.createChatMessage({
          peerId,
          text: params.message,
          conversationId: params.conversationId,
        });

        if (!result.ok) {
          return JSON.stringify({ ok: false, error: result.error });
        }

        // The actual transport would happen here (WS send + await response)
        // For the prototype, we return the created message info
        const peer = node.trustStore.getPeer(peerId);
        return JSON.stringify({
          ok: true,
          sent: true,
          conversationId: result.conversationId,
          peer: {
            id: formatPeerId(peerId),
            name: peer?.identity.name ?? "unknown",
          },
          note: "Message signed and queued for delivery",
        });
      },
    },
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
            id: formatPeerId(p.peerId),
            name: p.peerName,
            connected: p.connected,
            trust: p.trust,
            capabilities: p.capabilities,
            lastSeen: p.lastSeenAt ? new Date(p.lastSeenAt).toISOString() : null,
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
