/**
 * Federation Config — Zod schema, parser, and defaults.
 *
 * Validates the `federation:` section of config.yaml and produces
 * a strongly-typed {@link FederationConfig} at runtime.
 *
 * @module
 */

import { z } from "zod";
import type {
  CapabilityGrant,
  FederationCapability,
  FederationConfig,
  PeerEndpoint,
} from "./types.js";

// ─── Capability enum ────────────────────────────────────────

const FEDERATION_CAPABILITIES: readonly FederationCapability[] = [
  "chat",
  "calendar.read",
  "calendar.write",
  "weather",
  "location.city",
  "tasks.read",
  "tasks.write",
  "introduce",
] as const;

const FederationCapabilitySchema = z.enum(
  FEDERATION_CAPABILITIES as unknown as [string, ...string[]],
);

// ─── Rate Limit ─────────────────────────────────────────────

const RateLimitSchema = z
  .object({
    maxMessagesPerMinute: z.number().int().positive().max(10_000).optional(),
    maxMessagesPerHour: z.number().int().positive().max(100_000).optional(),
    maxMessagesPerDay: z.number().int().positive().max(1_000_000).optional(),
  })
  .strict()
  .superRefine((val, ctx) => {
    // Ensure ascending hierarchy: minute <= hour <= day
    if (
      val.maxMessagesPerMinute !== undefined &&
      val.maxMessagesPerHour !== undefined &&
      val.maxMessagesPerMinute > val.maxMessagesPerHour
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["maxMessagesPerMinute"],
        message: "maxMessagesPerMinute must not exceed maxMessagesPerHour",
      });
    }
    if (
      val.maxMessagesPerHour !== undefined &&
      val.maxMessagesPerDay !== undefined &&
      val.maxMessagesPerHour > val.maxMessagesPerDay
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["maxMessagesPerHour"],
        message: "maxMessagesPerHour must not exceed maxMessagesPerDay",
      });
    }
  });

export type FederationRateLimit = z.infer<typeof RateLimitSchema>;

// ─── Peer Endpoint ──────────────────────────────────────────

const PeerEndpointSchema = z
  .object({
    wsUrl: z.string().url().optional(),
    httpUrl: z.string().url().optional(),
    tlsFingerprint: z.string().optional(),
    tailnetHostname: z.string().optional(),
  })
  .strict()
  .refine(
    (ep) => ep.wsUrl || ep.httpUrl || ep.tailnetHostname,
    "Peer endpoint must specify at least one of wsUrl, httpUrl, or tailnetHostname",
  );

// ─── Trusted Peer (config-file representation) ─────────────

const TrustedPeerConfigSchema = z
  .object({
    /** Ed25519 public key — PEM or raw base64 */
    publicKey: z.string().min(16, "publicKey too short — expected Ed25519 PEM or base64"),
    /** Human-readable display name */
    name: z.string().min(1).max(128),
    /** Network endpoint(s) for this peer */
    endpoint: PeerEndpointSchema,
    /** Capabilities to grant on first handshake */
    capabilities: z.array(FederationCapabilitySchema).optional(),
    /** Per-peer rate limit (overrides defaultRateLimit) */
    rateLimit: RateLimitSchema.optional(),
  })
  .strict();

export type TrustedPeerConfig = z.infer<typeof TrustedPeerConfigSchema>;

// ─── Top-level Federation Config ────────────────────────────

/**
 * `FederationConfigZod` — the canonical Zod schema for the `federation:`
 * section of `config.yaml`.
 *
 * Used by the main {@link OpenClawSchema} to validate the full config tree.
 *
 * ```yaml
 * federation:
 *   enabled: true
 *   instanceName: "Ark"
 *   trustedPeers: [...]
 * ```
 */
export const FederationConfigZod = z
  .object({
    /** Enable the federation subsystem (default: false). */
    enabled: z.boolean().optional(),

    /**
     * Display name for this instance in federation handshakes.
     * Defaults to the system hostname if omitted.
     */
    instanceName: z.string().min(1).max(128).optional(),

    /**
     * Pre-approved peers loaded from config.
     * At runtime, additional peers may be added via the trust store.
     */
    trustedPeers: z.array(TrustedPeerConfigSchema).optional(),

    /**
     * Default rate limits applied to peers that do not specify their own.
     */
    defaultRateLimit: RateLimitSchema.optional(),

    /**
     * Allow peers to introduce other peers (Web of Trust expansion).
     * When false, only explicitly configured peers are trusted.
     */
    allowIntroductions: z.boolean().optional(),

    /**
     * Maximum trust chain depth for introductions.
     * - 1 = only directly trusted peers
     * - 2 = direct + one hop via introduction (default)
     * - 0 = unlimited (NOT recommended)
     */
    maxTrustDepth: z.number().int().min(0).max(10).optional(),

    /**
     * Filesystem path for the persistent trust store (SQLite or JSON).
     * Relative paths are resolved against the OpenClaw data directory.
     */
    trustStorePath: z.string().optional(),

    /**
     * Filesystem path for the Ed25519 keypair.
     * If missing, a new keypair is generated on first boot.
     */
    identityKeyPath: z.string().optional(),

    /**
     * Port for the dedicated federation WebSocket listener.
     * When omitted, federation piggybacks on the gateway port.
     */
    port: z.number().int().min(1).max(65535).optional(),

    /**
     * Bind address for the federation listener.
     * Follows the same semantics as `gateway.bind`.
     */
    bind: z
      .union([z.literal("auto"), z.literal("lan"), z.literal("loopback"), z.literal("tailnet")])
      .optional(),
  })
  .strict()
  .superRefine((val, ctx) => {
    // If introductions are disabled, maxTrustDepth > 1 is misleading
    if (
      val.allowIntroductions === false &&
      val.maxTrustDepth !== undefined &&
      val.maxTrustDepth > 1
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ["maxTrustDepth"],
        message: "maxTrustDepth > 1 has no effect when allowIntroductions is false",
      });
    }

    // Validate trustedPeers have unique names
    const peers = val.trustedPeers ?? [];
    const names = new Set<string>();
    for (let i = 0; i < peers.length; i++) {
      const name = peers[i].name;
      if (names.has(name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["trustedPeers", i, "name"],
          message: `Duplicate peer name "${name}" — each trusted peer must have a unique name`,
        });
      }
      names.add(name);
    }

    // Validate trustedPeers have unique publicKeys
    const keys = new Set<string>();
    for (let i = 0; i < peers.length; i++) {
      const key = peers[i].publicKey;
      if (keys.has(key)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["trustedPeers", i, "publicKey"],
          message: `Duplicate publicKey at peer "${peers[i].name}" — each peer must have a unique key`,
        });
      }
      keys.add(key);
    }
  });

// Re-export the inferred Zod type (useful for tests / type guards)
export type FederationConfigZodInferred = z.infer<typeof FederationConfigZod>;

// ─── Defaults ───────────────────────────────────────────────

const DEFAULT_RATE_LIMIT: NonNullable<FederationConfig["defaultRateLimit"]> = {
  maxMessagesPerMinute: 10,
  maxMessagesPerHour: 100,
  maxMessagesPerDay: 500,
};

/**
 * Returns a safe default `FederationConfig`.
 *
 * Federation is **disabled** by default — the user must explicitly opt in
 * by setting `federation.enabled: true` in config.yaml.
 */
export function defaultFederationConfig(): FederationConfig {
  return {
    enabled: false,
    instanceName: "openclaw",
    trustedPeers: [],
    defaultRateLimit: { ...DEFAULT_RATE_LIMIT },
    allowIntroductions: true,
    maxTrustDepth: 2,
  };
}

// ─── Parser ─────────────────────────────────────────────────

/**
 * Parse and validate a raw `federation:` config object.
 *
 * Returns a fully-typed {@link FederationConfig}, merging defaults for
 * any fields the user omitted.
 *
 * @param raw - The untyped value from config.yaml (or `undefined`).
 * @returns A validated and defaulted `FederationConfig`.
 * @throws {z.ZodError} if validation fails.
 *
 * @example
 * ```ts
 * import { parseFederationConfig } from "./config.js";
 *
 * const raw = yaml.parse(configFile).federation;
 * const cfg = parseFederationConfig(raw);
 * console.log(cfg.enabled);        // boolean
 * console.log(cfg.instanceName);   // string
 * ```
 */
export function parseFederationConfig(raw: unknown): FederationConfig {
  // If undefined/null, return defaults (federation is off)
  if (raw === undefined || raw === null) {
    return defaultFederationConfig();
  }

  const parsed = FederationConfigZod.parse(raw);
  const defaults = defaultFederationConfig();

  return {
    enabled: parsed.enabled ?? defaults.enabled,
    instanceName: parsed.instanceName ?? defaults.instanceName,
    trustedPeers: parsed.trustedPeers?.map((peer) => ({
      publicKey: peer.publicKey,
      name: peer.name,
      endpoint: peer.endpoint as PeerEndpoint,
      capabilities: peer.capabilities as FederationCapability[] | undefined,
      rateLimit: peer.rateLimit as CapabilityGrant["rateLimit"],
    })),
    defaultRateLimit: parsed.defaultRateLimit ?? defaults.defaultRateLimit,
    allowIntroductions: parsed.allowIntroductions ?? defaults.allowIntroductions,
    maxTrustDepth: parsed.maxTrustDepth ?? defaults.maxTrustDepth,
  };
}

// ─── Utility: merge a parsed peer with rate-limit defaults ──

/**
 * Resolve the effective rate limit for a peer, falling back to the
 * federation-level default when the peer has no per-peer override.
 */
export function resolveRateLimit(
  peerRateLimit: CapabilityGrant["rateLimit"] | undefined,
  federationDefault: CapabilityGrant["rateLimit"] | undefined,
): NonNullable<CapabilityGrant["rateLimit"]> {
  const base = federationDefault ?? DEFAULT_RATE_LIMIT;
  if (!peerRateLimit) {
    return { ...base };
  }
  return {
    maxMessagesPerMinute: peerRateLimit.maxMessagesPerMinute ?? base.maxMessagesPerMinute,
    maxMessagesPerHour: peerRateLimit.maxMessagesPerHour ?? base.maxMessagesPerHour,
    maxMessagesPerDay: peerRateLimit.maxMessagesPerDay ?? base.maxMessagesPerDay,
  };
}

// ─── Utility: validate a public key string ──────────────────

const PEM_HEADER = "-----BEGIN PUBLIC KEY-----";

/**
 * Quick heuristic check whether a string looks like an Ed25519 public key.
 * Does NOT perform cryptographic validation — that happens at handshake time.
 */
export function looksLikeEd25519PublicKey(key: string): boolean {
  if (key.startsWith(PEM_HEADER)) {
    return true;
  }
  // Raw base64 — Ed25519 public key is 32 bytes → 44 base64 chars (with padding)
  // or 43 without padding.  Allow a bit of slack for DER-wrapped keys (44-64 chars).
  const stripped = key.replace(/\s/g, "");
  return /^[A-Za-z0-9+/=]{32,128}$/.test(stripped);
}
