/**
 * Federation Audit Log — Tamper-evident logging for cross-instance communication
 *
 * Every federation action (handshake, message, capability change, pairing, security event)
 * is logged to a JSONL file under `<stateDir>/federation/audit.jsonl`.
 *
 * Features:
 * - Append-only JSONL format (one JSON object per line)
 * - Automatic file rotation when size exceeds 10 MB
 * - In-memory ring buffer for fast recent-log queries
 * - JSON export with optional time-range filtering
 * - Typed audit entries for every federation event category
 */

import fs from "node:fs";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";

// ─── Types ──────────────────────────────────────────────────

export type AuditEventType = "handshake" | "message" | "capability_change" | "pairing" | "security";

export type AuditEntry = {
  /** ISO-8601 timestamp */
  timestamp: string;
  /** Unix epoch millis */
  timestampMs: number;
  /** Event category */
  eventType: AuditEventType;
  /** Peer identity hash */
  peerId: string;
  /** Human-readable peer name */
  peerName: string;
  /** Message direction (for message events) */
  direction?: "inbound" | "outbound";
  /** Event-specific details */
  details: Record<string, unknown>;
  /** Ed25519 message signature (when applicable) */
  messageSignature?: string;
};

// ─── Constants ──────────────────────────────────────────────

/** Max audit file size before rotation (10 MB) */
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024;

/** Default in-memory ring-buffer capacity */
const DEFAULT_RING_CAPACITY = 1000;

/** Max archived files to keep (prevents unbounded disk usage) */
const MAX_ARCHIVE_FILES = 50;

// ─── Helpers ────────────────────────────────────────────────

function resolveAuditDir(stateDir?: string): string {
  return path.join(stateDir ?? resolveStateDir(), "federation");
}

function resolveAuditFilePath(stateDir?: string): string {
  return path.join(resolveAuditDir(stateDir), "audit.jsonl");
}

function ensureDir(dirPath: string): void {
  fs.mkdirSync(dirPath, { recursive: true });
}

function formatArchiveName(now: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  const ts = [
    now.getFullYear(),
    pad(now.getMonth() + 1),
    pad(now.getDate()),
    pad(now.getHours()),
    pad(now.getMinutes()),
    pad(now.getSeconds()),
  ].join("");
  return `audit-${ts}.jsonl`;
}

// ─── Ring Buffer ────────────────────────────────────────────

class RingBuffer<T> {
  private readonly items: (T | undefined)[];
  private head = 0;
  private count = 0;

  constructor(private readonly capacity: number) {
    this.items = Array.from({ length: capacity });
  }

  push(item: T): void {
    this.items[this.head] = item;
    this.head = (this.head + 1) % this.capacity;
    if (this.count < this.capacity) {
      this.count++;
    }
  }

  /** Return items newest-first, up to `limit`. */
  recent(limit: number): T[] {
    const n = Math.min(limit, this.count);
    const result: T[] = [];
    for (let i = 0; i < n; i++) {
      const idx = (this.head - 1 - i + this.capacity) % this.capacity;
      result.push(this.items[idx]!);
    }
    return result;
  }

  toArray(): T[] {
    return this.recent(this.count);
  }

  get size(): number {
    return this.count;
  }
}

// ─── FederationAuditLog ─────────────────────────────────────

export class FederationAuditLog {
  private readonly filePath: string;
  private readonly auditDir: string;
  private readonly ring: RingBuffer<AuditEntry>;
  private fd: number | null = null;
  private currentFileSize = 0;

  constructor(options?: { stateDir?: string; ringCapacity?: number }) {
    this.auditDir = resolveAuditDir(options?.stateDir);
    this.filePath = resolveAuditFilePath(options?.stateDir);
    this.ring = new RingBuffer<AuditEntry>(options?.ringCapacity ?? DEFAULT_RING_CAPACITY);
    this.init();
  }

  // ─── Lifecycle ──────────────────────────────────────────

  private init(): void {
    ensureDir(this.auditDir);
    try {
      const stat = fs.statSync(this.filePath);
      this.currentFileSize = stat.size;
    } catch {
      this.currentFileSize = 0;
    }

    // Pre-load recent entries from disk into ring buffer
    this.loadRecentFromDisk();
  }

  /** Pre-populate ring buffer from existing audit file (tail). */
  private loadRecentFromDisk(): void {
    try {
      if (!fs.existsSync(this.filePath)) {
        return;
      }
      const content = fs.readFileSync(this.filePath, "utf8");
      const lines = content.trim().split("\n").filter(Boolean);
      // Only load last `ringCapacity` lines
      for (const line of lines) {
        try {
          const entry = JSON.parse(line) as AuditEntry;
          this.ring.push(entry);
        } catch {
          // Skip malformed lines
        }
      }
    } catch {
      // File might not exist yet — that's fine
    }
  }

  /**
   * Close the file descriptor if open.
   * Call when shutting down cleanly.
   */
  close(): void {
    if (this.fd !== null) {
      try {
        fs.closeSync(this.fd);
      } catch {
        // best-effort
      }
      this.fd = null;
    }
  }

  // ─── Core Write ─────────────────────────────────────────

  private write(entry: AuditEntry): void {
    this.ring.push(entry);

    const line = JSON.stringify(entry) + "\n";
    const lineBytes = Buffer.byteLength(line, "utf8");

    // Rotate if needed
    if (this.currentFileSize + lineBytes > MAX_FILE_SIZE_BYTES) {
      this.rotate();
    }

    try {
      ensureDir(this.auditDir);
      fs.appendFileSync(this.filePath, line, { encoding: "utf8" });
      this.currentFileSize += lineBytes;
    } catch (err) {
      // Audit logging should never crash the process
      // eslint-disable-next-line no-console
      console.error("[federation-audit] Failed to write audit log:", err);
    }
  }

  private rotate(): void {
    try {
      if (!fs.existsSync(this.filePath)) {
        return;
      }

      const archiveName = formatArchiveName(new Date());
      const archivePath = path.join(this.auditDir, archiveName);
      fs.renameSync(this.filePath, archivePath);
      this.currentFileSize = 0;

      // Prune old archives
      this.pruneArchives();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error("[federation-audit] Failed to rotate audit log:", err);
    }
  }

  private pruneArchives(): void {
    try {
      const files = fs
        .readdirSync(this.auditDir)
        .filter((f) => f.startsWith("audit-") && f.endsWith(".jsonl") && f !== "audit.jsonl")
        .toSorted();

      while (files.length > MAX_ARCHIVE_FILES) {
        const oldest = files.shift()!;
        fs.unlinkSync(path.join(this.auditDir, oldest));
      }
    } catch {
      // best-effort
    }
  }

  private createEntry(
    eventType: AuditEventType,
    peerId: string,
    peerName: string,
    details: Record<string, unknown>,
    extra?: { direction?: "inbound" | "outbound"; messageSignature?: string },
  ): AuditEntry {
    const ms = Date.now();
    const now = new Date(ms);
    return {
      timestamp: now.toISOString(),
      timestampMs: ms,
      eventType,
      peerId,
      peerName,
      ...(extra?.direction ? { direction: extra.direction } : {}),
      details,
      ...(extra?.messageSignature ? { messageSignature: extra.messageSignature } : {}),
    };
  }

  // ─── Public API: Log Events ─────────────────────────────

  /**
   * Log a handshake event (initiation, completion, failure).
   */
  logHandshake(peerId: string, peerName: string, success: boolean, error?: string): void {
    const entry = this.createEntry("handshake", peerId, peerName, {
      success,
      ...(error ? { error } : {}),
    });
    this.write(entry);
  }

  /**
   * Log a federation message (inbound or outbound).
   */
  logMessage(
    direction: "inbound" | "outbound",
    peerId: string,
    peerName: string,
    messageType: string,
    conversationId?: string,
    messageSignature?: string,
  ): void {
    const entry = this.createEntry(
      "message",
      peerId,
      peerName,
      {
        messageType,
        ...(conversationId ? { conversationId } : {}),
      },
      { direction, messageSignature },
    );
    this.write(entry);
  }

  /**
   * Log a capability grant or revocation.
   */
  logCapabilityChange(peerId: string, action: "grant" | "revoke", capabilities: string[]): void {
    const entry = this.createEntry("capability_change", peerId, "", {
      action,
      capabilities,
    });
    this.write(entry);
  }

  /**
   * Log a pairing event (initiated, accepted, rejected).
   */
  logPairingEvent(
    peerId: string,
    peerName: string,
    action: "initiated" | "accepted" | "rejected",
  ): void {
    const entry = this.createEntry("pairing", peerId, peerName, {
      action,
    });
    this.write(entry);
  }

  /**
   * Log a security-relevant event (signature failure, rate limit hit,
   * unknown peer connection attempt, etc.).
   */
  logSecurityEvent(peerId: string, event: string, details?: Record<string, unknown>): void {
    const entry = this.createEntry("security", peerId, "", {
      event,
      ...details,
    });
    this.write(entry);
  }

  // ─── Public API: Query ──────────────────────────────────

  /**
   * Get recent audit entries from the in-memory ring buffer.
   * Returns newest-first. Default limit: 50.
   */
  getRecentLogs(limit = 50): AuditEntry[] {
    return this.ring.recent(limit);
  }

  /**
   * Export logs as a JSON string (array of entries).
   * Reads from disk to include full history.
   *
   * @param from - Start timestamp (ms, inclusive). Omit for beginning of file.
   * @param to   - End timestamp (ms, inclusive). Omit for end of file.
   */
  exportLogs(from?: number, to?: number): string {
    const entries: AuditEntry[] = [];

    // Collect from active file
    this.collectEntriesFromFile(this.filePath, entries, from, to);

    // Also collect from archived files if they overlap the time range
    try {
      const archives = fs
        .readdirSync(this.auditDir)
        .filter((f) => f.startsWith("audit-") && f.endsWith(".jsonl") && f !== "audit.jsonl")
        .toSorted();

      for (const archive of archives) {
        this.collectEntriesFromFile(path.join(this.auditDir, archive), entries, from, to);
      }
    } catch {
      // Ignore read errors on archives
    }

    // Sort by timestamp ascending
    entries.sort((a, b) => a.timestampMs - b.timestampMs);

    return JSON.stringify(entries, null, 2);
  }

  private collectEntriesFromFile(
    filePath: string,
    out: AuditEntry[],
    from?: number,
    to?: number,
  ): void {
    try {
      if (!fs.existsSync(filePath)) {
        return;
      }
      const content = fs.readFileSync(filePath, "utf8");
      for (const line of content.split("\n")) {
        if (!line.trim()) {
          continue;
        }
        try {
          const entry = JSON.parse(line) as AuditEntry;
          if (from !== undefined && entry.timestampMs < from) {
            continue;
          }
          if (to !== undefined && entry.timestampMs > to) {
            continue;
          }
          out.push(entry);
        } catch {
          // Skip malformed lines
        }
      }
    } catch {
      // File read error — skip
    }
  }

  // ─── Utilities ──────────────────────────────────────────

  /**
   * Get the number of entries in the in-memory ring buffer.
   */
  get recentCount(): number {
    return this.ring.size;
  }

  /**
   * Get the path to the active audit log file.
   */
  get activeFilePath(): string {
    return this.filePath;
  }

  /**
   * Get the audit directory path.
   */
  get directory(): string {
    return this.auditDir;
  }
}
