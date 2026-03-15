# Federation — Decentralized Multi-Instance Communication

Federation enables multiple OpenClaw instances to communicate securely over the
network, forming a **Web of Trust** between agents owned by different people.

## Architecture

```
  ┌──────────────┐        WSS / HTTPS        ┌──────────────┐
  │  Ark (you)   │ ◄─────────────────────────►│  Nova (peer) │
  │  Ed25519 ID  │   signed messages          │  Ed25519 ID  │
  │  Trust Store │   capability grants        │  Trust Store  │
  └──────────────┘                            └──────────────┘
```

Each instance has an **Ed25519 keypair**. The peer identity (`peerId`) is the
SHA-256 hash of the public key — similar to a wallet address. All messages are
**signed** for non-repudiation and tamper protection.

## Quick Start

### 1. Enable federation in `config.yaml`

```yaml
federation:
  enabled: true
  instanceName: "Ark"
```

On first boot with federation enabled, OpenClaw generates an Ed25519 keypair and
prints the public key to the log. Share this key with peers you want to connect.

### 2. Add trusted peers

```yaml
federation:
  enabled: true
  instanceName: "Ark"
  allowIntroductions: true
  maxTrustDepth: 2
  defaultRateLimit:
    maxMessagesPerMinute: 10
    maxMessagesPerHour: 100
    maxMessagesPerDay: 500
  trustedPeers:
    - name: "Nova"
      publicKey: "MCowBQYDK2VwAyEA..." # Ed25519 PEM or base64
      endpoint:
        wsUrl: "wss://nova.tailnet:18789/federation"
        httpUrl: "https://nova.tailnet:18789"
      capabilities: ["chat", "calendar.read", "weather"]
      rateLimit:
        maxMessagesPerMinute: 20
    - name: "Orion"
      publicKey: "MCowBQYDK2VwAyEB..."
      endpoint:
        tailnetHostname: "orion.tailnet"
      capabilities: ["chat", "tasks.read"]
```

### 3. Verify connectivity

```bash
openclaw federation status
```

This shows your identity, connected peers, trust levels, and capabilities.

## Configuration Reference

### `federation`

| Field                | Type            | Default      | Description                                                    |
| -------------------- | --------------- | ------------ | -------------------------------------------------------------- |
| `enabled`            | `boolean`       | `false`      | Master switch for the federation subsystem.                    |
| `instanceName`       | `string`        | `"openclaw"` | Display name shown to peers during handshakes.                 |
| `trustedPeers`       | `array`         | `[]`         | Pre-approved peers (see below).                                |
| `defaultRateLimit`   | `object`        | see below    | Default rate limits for peers without per-peer overrides.      |
| `allowIntroductions` | `boolean`       | `true`       | Allow peers to introduce other peers (Web of Trust expansion). |
| `maxTrustDepth`      | `number (0–10)` | `2`          | Max trust chain depth. `1` = direct only, `2` = one hop.       |
| `trustStorePath`     | `string`        | auto         | Path to persistent trust store (SQLite/JSON).                  |
| `identityKeyPath`    | `string`        | auto         | Path to Ed25519 keypair file. Auto-generated if missing.       |
| `port`               | `number`        | gateway port | Dedicated federation WS port (omit to share gateway port).     |
| `bind`               | `string`        | `"loopback"` | Bind mode: `auto`, `lan`, `loopback`, or `tailnet`.            |

### `federation.defaultRateLimit`

| Field                  | Type     | Default | Description                               |
| ---------------------- | -------- | ------- | ----------------------------------------- |
| `maxMessagesPerMinute` | `number` | `10`    | Max inbound messages per minute per peer. |
| `maxMessagesPerHour`   | `number` | `100`   | Max inbound messages per hour per peer.   |
| `maxMessagesPerDay`    | `number` | `500`   | Max inbound messages per day per peer.    |

### `federation.trustedPeers[*]`

| Field          | Type       | Required | Description                                               |
| -------------- | ---------- | -------- | --------------------------------------------------------- |
| `name`         | `string`   | ✅       | Unique display name for this peer.                        |
| `publicKey`    | `string`   | ✅       | Ed25519 public key (PEM or base64).                       |
| `endpoint`     | `object`   | ✅       | At least one of `wsUrl`, `httpUrl`, or `tailnetHostname`. |
| `capabilities` | `string[]` | ❌       | Capabilities to grant: `chat`, `calendar.read`, etc.      |
| `rateLimit`    | `object`   | ❌       | Per-peer rate limits (overrides `defaultRateLimit`).      |

### Available Capabilities

| Capability       | Description                          |
| ---------------- | ------------------------------------ |
| `chat`           | Send and receive chat messages       |
| `calendar.read`  | Query calendar events                |
| `calendar.write` | Create calendar events               |
| `weather`        | Query weather information            |
| `location.city`  | Know city-level location             |
| `tasks.read`     | Query shared tasks                   |
| `tasks.write`    | Create shared tasks                  |
| `introduce`      | Introduce other peers (Web of Trust) |

## Trust Model

Federation uses a **three-tier trust model**:

| Level     | Meaning                                            |
| --------- | -------------------------------------------------- |
| `direct`  | Owner explicitly verified this peer (key exchange) |
| `vouched` | A directly-trusted peer vouched for this one       |
| `unknown` | No trust established — messages rejected           |

**`maxTrustDepth`** controls how far introductions propagate:

- `1` — Only directly trusted peers (no introductions accepted)
- `2` — Direct peers + peers introduced by direct peers (default)
- `3+` — Deeper chains (use with caution)
- `0` — Unlimited depth (not recommended)

## Security

- **Ed25519 keypairs** — No shared secrets; asymmetric cryptography throughout.
- **Signed messages** — Every federation message carries an Ed25519 signature.
- **Replay protection** — Monotonic sequence numbers per peer session.
- **Capability grants** — Fine-grained, signed permission documents.
- **Isolated sessions** — Federation sessions use a restricted tool allowlist
  (no file/exec/memory access).
- **Rate limiting** — Per-peer, per-time-window limits to prevent abuse.

### What federation sessions CAN do

- Have normal conversations
- Share public information and general knowledge
- Answer questions about shared topics (weather, news, etc.)
- Relay messages between the external agent and your owner

### What federation sessions CANNOT do

- Read or share any local files
- Execute commands
- Access memory or conversation history
- Share owner's schedule, contacts, or preferences without approval

## Programmatic Usage

```ts
import { parseFederationConfig, defaultFederationConfig } from "./config.js";

// Parse from raw YAML object
const cfg = parseFederationConfig(rawYaml.federation);

// Or use defaults
const defaults = defaultFederationConfig();
// => { enabled: false, instanceName: "openclaw", ... }
```

### Resolve effective rate limit for a peer

```ts
import { resolveRateLimit } from "./config.js";

const effective = resolveRateLimit(
  peer.rateLimit, // per-peer override (may be undefined)
  cfg.defaultRateLimit, // federation-level default
);
// => { maxMessagesPerMinute: 20, maxMessagesPerHour: 100, maxMessagesPerDay: 500 }
```

## Files

| File                            | Description                             |
| ------------------------------- | --------------------------------------- |
| `types.ts`                      | Core federation type definitions        |
| `config.ts`                     | Zod schema, parser, defaults            |
| `../config/types.federation.ts` | TypeScript config types (TypeBox-style) |
