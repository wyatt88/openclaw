/**
 * Federation Tool — Agent tool for cross-instance communication
 *
 * Allows the Agent to send messages to peer OpenClaw instances
 * and receive responses. Uses the federation registry to look up peers.
 *
 * Usage in Agent context:
 *   federation_chat({ peerId: "nova", message: "What's the weather?" })
 */

import { Type } from "@sinclair/typebox";
import type { FederationRegistry } from "./client.js";

const FederationChatToolSchema = Type.Object({
  peerId: Type.String({
    description: "ID of the peer Gateway to communicate with",
  }),
  message: Type.String({
    description: "Message to send to the peer Agent",
  }),
  systemPrompt: Type.Optional(
    Type.String({
      description: "Optional system prompt to prepend",
    }),
  ),
  model: Type.Optional(
    Type.String({
      description: "Model override for the peer (default: peer's default model)",
    }),
  ),
});

const FederationListPeersToolSchema = Type.Object({});

const FederationHealthToolSchema = Type.Object({
  peerId: Type.Optional(
    Type.String({
      description: "Specific peer ID to check (omit for all peers)",
    }),
  ),
});

/**
 * Create federation tools for the Agent.
 */
export function createFederationTools(registry: FederationRegistry) {
  return [
    {
      label: "Federation Chat",
      name: "federation_chat",
      description:
        "Send a message to a peer OpenClaw instance and get a response. " +
        "Use this to communicate with other AI agents running on different OpenClaw Gateways.",
      parameters: FederationChatToolSchema,
      execute: async (_toolCallId: string, args: unknown) => {
        const params = args as {
          peerId: string;
          message: string;
          systemPrompt?: string;
          model?: string;
        };

        const result = await registry.chat({
          peerId: params.peerId,
          message: params.message,
          systemPrompt: params.systemPrompt,
          model: params.model,
        });

        if (!result.ok) {
          return JSON.stringify({
            ok: false,
            peerId: result.peerId,
            error: result.error,
            latencyMs: result.latencyMs,
          });
        }

        return JSON.stringify({
          ok: true,
          peerId: result.peerId,
          response: result.text,
          model: result.model,
          usage: result.usage,
          latencyMs: result.latencyMs,
        });
      },
    },
    {
      label: "Federation List Peers",
      name: "federation_list_peers",
      description:
        "List all known peer OpenClaw instances that this Gateway can communicate with.",
      parameters: FederationListPeersToolSchema,
      execute: async () => {
        const peers = registry.listPeers();
        const peerSummaries = peers.map((peer) => {
          const health = registry.getHealth(peer.id);
          return {
            id: peer.id,
            name: peer.name,
            url: peer.url,
            capabilities: peer.capabilities ?? ["chat"],
            health: health
              ? {
                  reachable: health.reachable,
                  latencyMs: health.latencyMs,
                  checkedAt: new Date(health.checkedAt).toISOString(),
                }
              : null,
          };
        });

        return JSON.stringify({
          peers: peerSummaries,
          count: peerSummaries.length,
        });
      },
    },
    {
      label: "Federation Health",
      name: "federation_health",
      description: "Check health/reachability of peer OpenClaw instances.",
      parameters: FederationHealthToolSchema,
      execute: async (_toolCallId: string, args: unknown) => {
        const params = args as { peerId?: string };

        if (params.peerId) {
          const peer = registry.getPeer(params.peerId);
          if (!peer) {
            return JSON.stringify({
              ok: false,
              error: `Unknown peer: ${params.peerId}`,
            });
          }
          const { checkPeerHealth } = await import("./client.js");
          const health = await checkPeerHealth(peer);
          return JSON.stringify(health);
        }

        const results = await registry.checkAllHealth();
        return JSON.stringify({
          peers: results,
          summary: {
            total: results.length,
            reachable: results.filter((r) => r.reachable).length,
            unreachable: results.filter((r) => !r.reachable).length,
          },
        });
      },
    },
  ];
}
