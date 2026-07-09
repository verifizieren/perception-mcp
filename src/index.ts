import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { WebSocketServer, WebSocket } from "ws";
import * as crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

// ─── WebSocket Bridge (multi-instance safe) ──────────────────────────
//
// Architecture:
//   Instance 1 (hub):  WS Server :9001  ← Perception AS connects here
//                                        ← Relay MCP instances also connect here
//   Instance 2+ (relay): WS Client → :9001, sends commands via hub
//
// Hub identifies clients by a handshake:
//   - Relay clients send: {"_mcp_relay": true} on connect
//   - Perception client doesn't send this
// Hub routes responses back to the correct relay client using _id prefix.

const WS_PORT = 9001;
// Shared secret pinned to the current OS user. Hub writes it 0600 on first launch,
// clients read it and include in the handshake. Blocks other local users from
// hijacking the WS server even though we bind loopback.
const TOKEN_PATH = path.join(os.tmpdir(), `perception-mcp-${os.userInfo().username}.token`);
function loadOrCreateToken(): string {
  // Multiple MCP instances may race to create the token file. Handle it:
  //   - try read first
  //   - on miss, try exclusive create (`wx`) so only one writer wins
  //   - if create races and loses (EEXIST), re-read the winner's token
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const t = fs.readFileSync(TOKEN_PATH, "utf8").trim();
      if (t.length >= 32) return t;
    } catch { /* not created yet */ }
    const t = crypto.randomBytes(32).toString("hex");
    try {
      fs.writeFileSync(TOKEN_PATH, t, { mode: 0o600, flag: "wx" });
      return t;
    } catch (e: any) {
      if (e && e.code === "EEXIST") continue; // another process won; loop and read theirs
      throw e;
    }
  }
  throw new Error("Failed to load or create auth token after 3 attempts");
}
const AUTH_TOKEN = loadOrCreateToken();

let pendingRequests = new Map<string, { resolve: (v: any) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> | undefined }>();
let requestId = 0;
let instanceId = `mcp_${process.pid}_${Date.now()}`;
let isHub = false;

// Hub state
let percClient: WebSocket | null = null;
let relayClients = new Map<string, WebSocket>(); // instanceId -> ws

// Relay state
let hubConnection: WebSocket | null = null;

// ─── Hub Mode (first instance) ──────────────────────────────────────
// Tries to bind the WS server. Resolves true on success, false if EADDRINUSE
// or any other listen error. Much more reliable than a separate "is port free"
// probe, which races with TIME_WAIT sockets and other relays trying to promote.
function tryStartHub(): Promise<boolean> {
  return new Promise((resolve) => {
    const wss = new WebSocketServer({ host: "127.0.0.1", port: WS_PORT });

    const onError = (err: any) => {
      if (err && err.code === "EADDRINUSE") {
        resolve(false);
      } else {
        console.error("[perception-mcp] Hub listen error:", err);
        resolve(false);
      }
    };
    wss.once("error", onError);

    wss.once("listening", () => {
      wss.removeListener("error", onError);
      isHub = true;
      console.error(`[perception-mcp] HUB mode — WebSocket server on ws://127.0.0.1:${WS_PORT}`);
      attachHubHandlers(wss);
      resolve(true);
    });
  });
}

function attachHubHandlers(wss: WebSocketServer) {
  // Server-level error (bind races, unhandled internals). Log; do not crash.
  wss.on("error", (err) => {
    console.error("[perception-mcp] WebSocketServer error:", err);
  });

  wss.on("connection", (ws) => {
    let clientType: "unknown" | "perception" | "relay" = "unknown";
    let relayId = "";

    // Per-socket error handler — without this, invalid frames (bad UTF-8,
    // protocol errors) throw an unhandled 'error' event and crash the whole
    // MCP process. We absorb the error; the 'close' event will clean up.
    ws.on("error", (err) => {
      console.error(`[perception-mcp] WS error (${clientType}):`, err.message || err);
    });

    // Unauthenticated sockets get 2s to identify + present the token; then dropped.
    const identifyTimeout = setTimeout(() => {
      if (clientType === "unknown") {
        console.error("[perception-mcp] Dropping unauthenticated WS connection (no handshake in 2s)");
        try { ws.close(1008, "handshake required"); } catch {}
      }
    }, 2000);

    // Constant-time token check (both strings are hex, same length when valid).
    function tokenOk(t: unknown): boolean {
      if (typeof t !== "string" || t.length !== AUTH_TOKEN.length) return false;
      try { return crypto.timingSafeEqual(Buffer.from(t), Buffer.from(AUTH_TOKEN)); }
      catch { return false; }
    }

    ws.on("message", (data) => {
      try {
        const msg = JSON.parse(data.toString());

        // Handshake from relay client
        if (clientType === "unknown" && msg._mcp_relay) {
          if (!tokenOk(msg._token)) { try { ws.close(1008, "bad token"); } catch {} return; }
          clearTimeout(identifyTimeout);
          clientType = "relay";
          relayId = msg._instance_id || `relay_${Date.now()}`;
          relayClients.set(relayId, ws);
          console.error(`[perception-mcp] Relay MCP instance connected: ${relayId}`);
          ws.send(JSON.stringify({ _mcp_relay_ack: true }));
          return;
        }

        // Handshake from Perception AngelScript client.
        // Token support is optional here: AngelScript may not have file I/O available
        // to read the token file, so we accept the legacy hello. Loopback bind is
        // the primary defense; token adds defense-in-depth for the relay path.
        if (clientType === "unknown" && (msg._mcp_perception || msg._perception_hello)) {
          if (typeof msg._token === "string" && !tokenOk(msg._token)) {
            try { ws.close(1008, "bad token"); } catch {} return;
          }
          if (!msg._token) {
            console.error("[perception-mcp] Perception hello without token — accepted (loopback-only bind); OK if AngelScript has no file I/O");
          }
          clearTimeout(identifyTimeout);
          clientType = "perception";
          percClient = ws;
          console.error("[perception-mcp] Perception AngelScript client connected");

          // Hub-side keepalive: send a text ping every 25s so the TCP idle timer
          // on either side never fires. The AngelScript client silently drops it.
          const hubPingInterval = setInterval(() => {
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ _hub_ping: true }));
            } else {
              clearInterval(hubPingInterval);
            }
          }, 25000);
          ws.on("close", () => clearInterval(hubPingInterval));
          return;
        }

        // Any other pre-handshake message → drop the connection.
        if (clientType === "unknown") {
          console.error("[perception-mcp] Dropping WS connection: missing handshake");
          try { ws.close(1008, "handshake required"); } catch {}
          return;
        }

        if (clientType === "perception") {
          // Process lifecycle events from AngelScript auto-reattach
          if (msg._event) {
            console.error(`[perception-mcp] Event: ${msg._event} — ${msg.detail || ""}`);
            // Broadcast to all relay clients so they know too
            for (const [, rws] of relayClients) {
              if (rws.readyState === WebSocket.OPEN) {
                rws.send(JSON.stringify(msg));
              }
            }
            return;
          }

          // Response from Perception — route to correct requester
          const id: string = msg._id;
          if (!id) return; // hub pings and keepalives arrive here — silently ignored

          // Check if it's for a relay client (id starts with relay's instanceId)
          let routed = false;
          for (const [rid, rws] of relayClients) {
            if (id.startsWith(rid + "_") && rws.readyState === WebSocket.OPEN) {
              rws.send(JSON.stringify(msg));
              routed = true;
              break;
            }
          }

          // Otherwise it's for the hub's own pending requests
          if (!routed && pendingRequests.has(id)) {
            const pending = pendingRequests.get(id)!;
            clearTimeout(pending.timer);
            pendingRequests.delete(id);
            delete msg._id;
            pending.resolve(msg);
          }
        }

        if (clientType === "relay") {
          // Command from relay — forward to Perception
          if (percClient && percClient.readyState === WebSocket.OPEN) {
            percClient.send(JSON.stringify(msg));
          } else {
            // Send error back to relay
            ws.send(JSON.stringify({ _id: msg._id, error: "Perception not connected" }));
          }
        }
      } catch (e) {
        console.error("[perception-mcp] Bad message:", e);
      }
    });

    ws.on("close", () => {
      if (clientType === "perception") {
        console.error("[perception-mcp] Perception client disconnected");
        // Only clear if this socket is still the active Perception client —
        // otherwise a stale-socket close would null out a newer connection.
        if (percClient === ws) {
          percClient = null;
          // Reject all pending requests
          for (const [id, pending] of pendingRequests) {
            clearTimeout(pending.timer);
            pending.reject(new Error("Perception client disconnected"));
          }
          pendingRequests.clear();
        }
      }
      if (clientType === "relay" && relayId) {
        console.error(`[perception-mcp] Relay instance disconnected: ${relayId}`);
        relayClients.delete(relayId);
      }
    });
  });
}

// ─── Relay Mode (subsequent instances) ───────────────────────────────
let relayRetryTimer: ReturnType<typeof setTimeout> | null = null;

function connectToHub() {
  console.error(`[perception-mcp] RELAY: connecting to hub at ws://127.0.0.1:${WS_PORT}...`);
  const ws = new WebSocket(`ws://127.0.0.1:${WS_PORT}`);

  ws.on("open", () => {
    hubConnection = ws;
    ws.send(JSON.stringify({ _mcp_relay: true, _instance_id: instanceId, _token: AUTH_TOKEN }));
    console.error(`[perception-mcp] RELAY: connected to hub (${instanceId})`);
    if (relayRetryTimer) { clearTimeout(relayRetryTimer); relayRetryTimer = null; }
  });

  ws.on("message", (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg._mcp_relay_ack) return;
      const id: string = msg._id;
      if (id && pendingRequests.has(id)) {
        const pending = pendingRequests.get(id)!;
        clearTimeout(pending.timer);
        pendingRequests.delete(id);
        delete msg._id;
        pending.resolve(msg);
      }
    } catch (e) {
      console.error("[perception-mcp] Bad hub message:", e);
    }
  });

  ws.on("close", () => {
    console.error("[perception-mcp] RELAY: disconnected from hub, retrying in 3s...");
    hubConnection = null;
    for (const [, pending] of pendingRequests) {
      clearTimeout(pending.timer);
      pending.reject(new Error("Hub disconnected"));
    }
    pendingRequests.clear();
    scheduleReconnect();
  });

  ws.on("error", () => {
    // close event fires after this, which triggers reconnect
  });
}

function scheduleReconnect() {
  if (relayRetryTimer) return;
  // Jitter (0.5–1.5s) so two relays don't race to bind the port at the same ms.
  const delay = 500 + Math.floor(Math.random() * 1000);
  relayRetryTimer = setTimeout(async () => {
    relayRetryTimer = null;
    // Before reconnecting as relay, try to promote ourselves to hub. If the
    // previous hub died, the port is now free and someone needs to take over.
    // Only one relay wins the bind; the others fall through to relay mode.
    const becameHub = await tryStartHub();
    if (becameHub) {
      console.error("[perception-mcp] Promoted from RELAY to HUB");
      return;
    }
    connectToHub();
  }, delay);
}

function startRelay() {
  isHub = false;
  connectToHub();
}

// ─── Send Command (works in both hub and relay mode) ─────────────────
function sendCommand(cmd: string, params: Record<string, any> = {}, timeoutMs = 30000): Promise<any> {
  return new Promise((resolve, reject) => {
    // Hub mode: send directly to Perception
    if (isHub) {
      if (!percClient || percClient.readyState !== WebSocket.OPEN) {
        return reject(new Error("Perception AngelScript not connected. Load re_server.as in Perception first."));
      }
      const id = `${instanceId}_req_${++requestId}`;
      const timer = timeoutMs > 0 ? setTimeout(() => {
        pendingRequests.delete(id);
        reject(new Error(`Request timed out after ${timeoutMs}ms`));
      }, timeoutMs) : undefined;

      pendingRequests.set(id, { resolve, reject, timer });
      percClient.send(JSON.stringify({ _id: id, cmd, ...params }));
    }
    // Relay mode: send through hub
    else {
      if (!hubConnection || hubConnection.readyState !== WebSocket.OPEN) {
        return reject(new Error("Not connected to hub. Is the first Claude Code instance still running?"));
      }
      const id = `${instanceId}_req_${++requestId}`;
      const timer = timeoutMs > 0 ? setTimeout(() => {
        pendingRequests.delete(id);
        reject(new Error(`Request timed out after ${timeoutMs}ms`));
      }, timeoutMs) : undefined;

      pendingRequests.set(id, { resolve, reject, timer });
      hubConnection.send(JSON.stringify({ _id: id, cmd, ...params }));
    }
  });
}

async function callTool(cmd: string, params: Record<string, any> = {}, timeoutMs = 30000): Promise<string> {
  const result = await sendCommand(cmd, params, timeoutMs);
  if (result.error) throw new Error(result.error);
  return JSON.stringify(result);
}

// ─── MCP Server ──────────────────────────────────────────────────────
const server = new McpServer({
  name: "perception-re",
  version: "1.0.0",
});


// ── Dispatcher pattern ───────────────────────────────────────────────
//
// 44 individual tools were collapsed into 9 category dispatchers. Each
// takes an `op` selector plus a shared bag of optional args. This drops
// the schema footprint loaded into the model's context from ~44 tool
// definitions to 9, without removing any capability. The AngelScript
// server (re_server.as) is unchanged — dispatchers map each op back to
// the original cmd string, applying the same CSV/JSON transforms and
// per-op timeouts the old wrappers used.

type OpSpec = {
  cmd: string;
  timeout?: number;
  required?: string[];  // fields that must be present & non-empty (arrays must be non-empty)
  hex?: string[];       // fields that, if present, must be valid hex addresses
  build?: (p: any) => Record<string, any>;
};

const HEX_RE = /^0x[0-9a-fA-F]+$|^[0-9a-fA-F]+$/;

function assertHex(v: any, label: string) {
  if (typeof v !== "string" || !HEX_RE.test(v.trim()))
    throw new Error(`${label} must be a hex value (e.g. 0x1a0), got: ${JSON.stringify(v)}`);
}
// Type-aware write token validation. Unsigned rejects negatives; float rejects hex; 64-bit demands strings.
function assertWriteToken(type: string, v: any, label: string) {
  const unsigned = type[0] === "u";
  const isFloat = type === "f32" || type === "f64";
  const is64 = type === "u64" || type === "i64";
  if (is64 && typeof v !== "string")
    throw new Error(`${label}: ${type} writes require a string ("0x..." or decimal) to avoid JS precision loss`);
  if (isFloat) {
    if (typeof v === "number") return;
    if (typeof v === "string" && /^-?\d+(\.\d+)?([eE][+-]?\d+)?$/.test(v.trim())) return;
    throw new Error(`${label}: ${type} needs a decimal number (no hex; use a u32/u64 write for bit patterns)`);
  }
  if (unsigned) {
    if (typeof v === "number") { if (Number.isInteger(v) && v >= 0) return; throw new Error(`${label}: ${type} needs a non-negative integer`); }
    if (typeof v === "string" && /^(0x[0-9a-fA-F]+|\d+)$/.test(v.trim())) return;
    throw new Error(`${label}: ${type} needs an unsigned integer or hex string (no negatives)`);
  }
  // signed integer
  if (typeof v === "number") { if (Number.isInteger(v)) return; throw new Error(`${label}: ${type} needs an integer`); }
  if (typeof v === "string" && /^-?(0x[0-9a-fA-F]+|\d+)$/.test(v.trim())) return;
  throw new Error(`${label}: ${type} needs a signed integer or hex string`);
}

function validate(spec: OpSpec, p: any) {
  for (const f of spec.required ?? []) {
    const v = p[f];
    if (v === undefined || v === null || v === "") throw new Error(`missing required field: ${f}`);
    if (Array.isArray(v) && v.length === 0) throw new Error(`field ${f} must be non-empty`);
  }
  for (const f of spec.hex ?? []) {
    const v = p[f];
    if (v === undefined || v === null || v === "") continue;
    assertHex(v, `field ${f}`);
  }
}

async function dispatch(table: Record<string, OpSpec>, op: string, p: any) {
  const spec = table[op];
  if (!spec) {
    const ops = Object.keys(table).join(", ");
    return { content: [{ type: "text" as const, text: `error: unknown op "${op}". valid ops: ${ops}` }] };
  }
  let params: Record<string, any>;
  try {
    validate(spec, p);
    params = spec.build ? spec.build(p) : p;
  } catch (e: any) {
    return { content: [{ type: "text" as const, text: `error: ${e.message}` }] };
  }
  const res = await callTool(spec.cmd, params, spec.timeout ?? 30000);
  return { content: [{ type: "text" as const, text: res }] };
}

// ── re_proc: process lifecycle ───────────────────────────────────────
server.tool(
  "re_proc",
  "Process lifecycle & validation. ops: attach {name?|pid?}, detach {}, info {}, is_valid {address}, tebs {}",
  { op: z.enum(["attach","detach","info","is_valid","tebs"]).describe("Operation"),
    name:    z.string().optional().describe("attach: process name e.g. 'notepad.exe'"),
    pid:     z.number().int().positive().optional().describe("attach: process id"),
    address: z.string().optional().describe("is_valid: hex address") },
  async (p) => dispatch({
    attach:   { cmd: "attach",           build: x => ({ name: x.name, pid: x.pid }) },
    detach:   { cmd: "detach",           build: () => ({}) },
    info:     { cmd: "process_info",     build: () => ({}) },
    is_valid: { cmd: "is_valid_address", required: ["address"], hex: ["address"], build: x => ({ address: x.address }) },
    tebs:     { cmd: "get_tebs",         build: () => ({}) },
  }, p.op, p)
);

// ── re_read: typed / structured memory reads ─────────────────────────
server.tool(
  "re_read",
  "Read memory. ops: bytes {address,size}, values {address,type,count?}, string {address,max_length?}, wstring {address,max_length?}, ptr_chain {base,offsets[],final_type?}, struct {address,fields[]}, ptr_array {address,count,offset_delta?}, hex_dump {address,size?}, filter_ptrs {base,count,vtable_check_addr,stride?,deref_offset?}. types: u8..i64,f32,f64 (+ptr for ptr_chain).",
  { op: z.enum(["bytes","values","string","wstring","ptr_chain","struct","ptr_array","hex_dump","filter_ptrs"]).describe("Operation"),
    address:  z.string().optional().describe("Base/target hex address"),
    base:     z.string().optional().describe("ptr_chain/filter_ptrs: base hex address"),
    size:     z.number().int().min(1).max(1048576).optional().describe("bytes: byte count (>64KB needs raw:true, max 1MB). hex_dump: default 256, max 4096"),
    max_length: z.number().int().min(1).max(65536).optional().describe("string/wstring: max chars (default 256, max 65536)"),
    count:    z.number().int().min(1).max(2048).optional().describe("values (max 1024) / ptr_array (max 4096) / filter_ptrs (max 2048): element count"),
    type:     z.enum(["u8","u16","u32","u64","i8","i16","i32","i64","f32","f64"]).optional().describe("values: value type"),
    offsets:  z.array(z.string()).optional().describe("ptr_chain: hex offsets e.g. ['0x308','0x330']"),
    final_type: z.enum(["u8","u16","u32","u64","i8","i16","i32","i64","f32","f64","ptr"]).optional().describe("ptr_chain: type at final addr (default ptr)"),
    verbose:  z.boolean().optional().describe("ptr_chain: include per-step chain trace (default false = final addr/value only)"),
    fields:   z.array(z.object({
      name: z.string(), offset: z.string(),
      type: z.enum(["u8","u16","u32","u64","i8","i16","i32","i64","f32","f64","string","wstring","ptr"]),
      max_chars: z.number().int().min(1).max(65536).optional()
    })).optional().describe("struct: field descriptors"),
    offset_delta: z.number().int().min(-1048576).max(1048576).optional().describe("ptr_array: offset added to each pointer (default 0)"),
    stride:   z.number().int().min(1).max(4096).optional().describe("filter_ptrs: bytes between pointers (default 8)"),
    vtable_check_addr: z.string().optional().describe("filter_ptrs: *ptr+deref_offset must equal this"),
    deref_offset: z.number().int().min(-4096).max(65536).optional().describe("filter_ptrs: offset in deref'd object (default 0=vtable)"),
    raw:      z.boolean().optional().describe("bytes: allow >64KB reads (default false)") },
  async (p) => dispatch({
    bytes:     { cmd: "read_memory",        required: ["address","size"], hex: ["address"], build: x => ({ address: x.address, size: x.size, raw: x.raw ?? false }) },
    values:    { cmd: "read_values",        required: ["address","type"], hex: ["address"], build: x => { if (x.count !== undefined && (x.count < 1 || x.count > 1024)) throw new Error("values.count must be 1..1024"); return { address: x.address, type: x.type, count: x.count ?? 1 }; } },
    string:    { cmd: "read_string",        required: ["address"], hex: ["address"], build: x => ({ address: x.address, max_length: x.max_length ?? 256 }) },
    wstring:   { cmd: "read_wstring",       required: ["address"], hex: ["address"], build: x => ({ address: x.address, max_length: x.max_length ?? 256 }) },
    ptr_chain: { cmd: "read_pointer_chain", required: ["base","offsets"], hex: ["base"], build: x => { if ((x.offsets ?? []).length > 32) throw new Error("ptr_chain.offsets must have ≤32 entries"); (x.offsets ?? []).forEach((o: any, i: number) => assertHex(o, `offsets[${i}]`)); return { base: x.base, offsets_csv: (x.offsets ?? []).join(","), final_type: x.final_type ?? "ptr", verbose: x.verbose ?? false }; } },
    struct:    { cmd: "read_struct",        required: ["address","fields"], hex: ["address"], build: x => { if ((x.fields ?? []).length > 256) throw new Error("struct.fields must have ≤256 entries"); (x.fields ?? []).forEach((f: any, i: number) => assertHex(f.offset, `fields[${i}].offset`)); return { address: x.address, fields_json: JSON.stringify(x.fields ?? []) }; } },
    ptr_array: { cmd: "read_pointer_array", required: ["address","count"], hex: ["address"], build: x => { if (x.count < 1 || x.count > 4096) throw new Error("ptr_array.count must be 1..4096"); return { address: x.address, count: x.count, offset_delta: x.offset_delta ?? 0 }; } },
    hex_dump:  { cmd: "hex_dump",           required: ["address"], hex: ["address"], build: x => { if (x.size !== undefined && (x.size < 1 || x.size > 4096)) throw new Error("hex_dump.size must be 1..4096"); return { address: x.address, size: x.size ?? 256 }; } },
    filter_ptrs: { cmd: "read_and_filter_pointers", required: ["base","count","vtable_check_addr"], hex: ["base","vtable_check_addr"], build: x => { if (x.count < 1 || x.count > 2048) throw new Error("filter_ptrs.count must be 1..2048"); return { base: x.base, count: x.count, stride: x.stride ?? 8, vtable_check_addr: x.vtable_check_addr, deref_offset: x.deref_offset ?? 0 }; } },
  }, p.op, p)
);

// ── re_write: memory writes ──────────────────────────────────────────
server.tool(
  "re_write",
  "Write memory. ops: bytes {address,data(hex)}, values {address,type,values[]}, string {address,text}, wstring {address,text}. types: u8..i64,f32,f64",
  { op: z.enum(["bytes","values","string","wstring"]).describe("Operation"),
    address: z.string().describe("Target hex address"),
    data:    z.string().optional().describe("bytes: hex-encoded bytes"),
    type:    z.enum(["u8","u16","u32","u64","i8","i16","i32","i64","f32","f64"]).optional().describe("values: value type"),
    values:  z.array(z.union([z.number(), z.string()])).optional().describe("values: numbers or hex strings ('0x...' for exact 64-bit)"),
    text:    z.string().optional().describe("string/wstring: text to write (null-terminated)") },
  async (p) => dispatch({
    bytes:   { cmd: "write_memory",  required: ["address","data"], hex: ["address"], build: x => {
                 if (typeof x.data !== "string" || !/^[0-9a-fA-F]+$/.test(x.data)) throw new Error("data: hex string only (no 0x prefix)");
                 if (x.data.length & 1) throw new Error("data: odd hex length");
                 if (x.data.length > 2 * 1048576) throw new Error("data: max 1MB (2M hex chars)");
                 return { address: x.address, data: x.data };
               } },
    values:  { cmd: "write_values",  required: ["address","type","values"], hex: ["address"], build: x => {
                 const arr = x.values ?? [];
                 if (arr.length > 4096) throw new Error("values: max 4096 entries per call");
                 arr.forEach((v: any, i: number) => assertWriteToken(x.type, v, `values[${i}]`));
                 return { address: x.address, type: x.type, values_csv: arr.map((v: any) => String(v)).join(",") };
               } },
    string:  { cmd: "write_string",  required: ["address","text"], hex: ["address"], build: x => { if (x.text.length > 65536) throw new Error("write_string.text > 65536 chars"); return { address: x.address, text: x.text }; } },
    wstring: { cmd: "write_wstring", required: ["address","text"], hex: ["address"], build: x => { if (x.text.length > 65536) throw new Error("write_wstring.text > 65536 chars"); return { address: x.address, text: x.text }; } },
  }, p.op, p)
);

// ── re_scan: pattern & value scanning ────────────────────────────────
server.tool(
  "re_scan",
  "Search process memory. ops: pattern {signature,start?,size?,module_name?} (first match), pattern_all {signature,...,max_results?}, value {type,value,heap_only?,page_offset?,page_limit?}, ptr_to {target,heap_only?,page_offset?,page_limit?}, heap_regions {regions[],type,value,max_results?,alignment?,max_total_bytes?} (chunks all regions with overlap; alignment default=val_size), xrefs {target,start?,size?,module_name?}, string_refs {search_text} (whole-process). NOTE: pattern/xrefs with no module_name/start+size scan 256MB from process base. page_limit/max_results cap RETURNED results, not scan cost. Heavy scans have a caller-side 120s timeout; the AS loop is not cancelled.",
  { op: z.enum(["pattern","pattern_all","value","ptr_to","heap_regions","xrefs","string_refs"]).describe("Operation"),
    signature: z.string().optional().describe("pattern/pattern_all: IDA-style e.g. '48 8B ?? ?? ?? 89'"),
    start:     z.string().optional().describe("pattern/xrefs: start hex addr (default module base)"),
    size:      z.string().optional().describe("pattern/xrefs: region size in hex"),
    module_name: z.string().optional().describe("Module to scan (default main)"),
    max_results: z.number().int().min(1).max(5000).optional().describe("pattern_all/heap_regions: cap on matches (max 5000)"),
    type:      z.enum(["u32","u64","float","double","string","wstring","pointer"]).optional().describe("value: scan type. heap_regions: u32|u64|pointer"),
    value:     z.union([z.string(), z.number()]).optional().describe("value/heap_regions: hex string for u64/pointer, number for u32/float/double"),
    target:    z.string().optional().describe("ptr_to/xrefs: target hex address"),
    heap_only: z.boolean().optional().describe("value/ptr_to: only heap regions (default false)"),
    page_offset: z.number().int().min(0).max(1000000).optional().describe("value/ptr_to: skip N results (default 0)"),
    page_limit:  z.number().int().min(1).max(5000).optional().describe("value/ptr_to: max returned (default 100, max 5000)"),
    regions:   z.array(z.object({ start: z.string(), size: z.string() })).optional().describe("heap_regions: from get_vad_snapshot (re_vm vad)"),
    alignment: z.number().int().refine(v => v===1||v===2||v===4||v===8, { message:"alignment must be 1|2|4|8" }).optional().describe("heap_regions: byte stride between value probes (1|2|4|8). Default = val_size (fast, aligned-only). Use 1 for unaligned hits (slow)."),
    max_total_bytes: z.number().int().min(1).max(17179869184).optional().describe("heap_regions: total scan budget across all regions (default 4GB, max 16GB). Sets budget_exceeded:true if hit."),
    search_text: z.string().optional().describe("string_refs: text to find refs to"),
    max_strings: z.number().int().min(1).max(100).optional().describe("string_refs: max distinct string addrs to trace (default 20, max 100)"),
    max_refs_per_string: z.number().int().min(1).max(200).optional().describe("string_refs: max ptr refs per string (default 50, max 200)"),
    max_total_refs: z.number().int().min(1).max(2000).optional().describe("string_refs: hard cap on total refs returned (default 500, max 2000)") },
  async (p) => dispatch({
    pattern:      { cmd: "pattern_scan",     required: ["signature"], hex: ["start","size"], build: x => ({ signature: x.signature, start: x.start, size: x.size, module_name: x.module_name }) },
    pattern_all:  { cmd: "pattern_scan_all", timeout: 120000, required: ["signature"], hex: ["start","size"], build: x => ({ signature: x.signature, start: x.start, size: x.size, module_name: x.module_name, max_results: x.max_results }) },
    value:        { cmd: "scan_value",       timeout: 120000, required: ["type","value"], build: x => {
                      const numT = x.type === "u32" || x.type === "float" || x.type === "double";
                      const hexT = x.type === "u64" || x.type === "pointer";
                      if (numT && typeof x.value !== "number") throw new Error(`${x.type} scan requires a numeric value`);
                      if (hexT) assertHex(x.value, `${x.type} value`);
                      if ((x.type === "string" || x.type === "wstring") && typeof x.value !== "string") throw new Error(`${x.type} scan requires a string value`);
                      return { type: x.type, value: hexT ? String(x.value) : x.value, heap_only: x.heap_only, page_offset: x.page_offset, page_limit: x.page_limit };
                    } },
    ptr_to:       { cmd: "scan_pointer_to",  timeout: 120000, required: ["target"], hex: ["target"], build: x => ({ target: x.target, heap_only: x.heap_only, page_offset: x.page_offset, page_limit: x.page_limit }) },
    heap_regions: { cmd: "scan_heap_regions", timeout: 120000, required: ["regions","type","value"], build: x => {
                      const hexT = x.type === "u64" || x.type === "pointer";
                      if (x.type === "u32" && typeof x.value !== "number") throw new Error("u32 scan requires a numeric value");
                      if (hexT) assertHex(x.value, `${x.type} value`);
                      (x.regions ?? []).forEach((r: any, i: number) => { assertHex(r.start, `regions[${i}].start`); assertHex(r.size, `regions[${i}].size`); });
                      return { regions_csv: (x.regions ?? []).map((r: any) => `${r.start}:${r.size}`).join(","), type: x.type, value: hexT ? String(x.value) : x.value, max_results: x.max_results ?? 100, alignment: x.alignment, max_total_bytes: x.max_total_bytes };
                    } },
    xrefs:        { cmd: "find_xrefs",       timeout: 120000, required: ["target"], hex: ["target","start","size"], build: x => ({ target: x.target, start: x.start, size: x.size, module_name: x.module_name }) },
    string_refs:  { cmd: "find_string_refs", timeout: 120000, required: ["search_text"], build: x => ({ search_text: x.search_text, max_strings: x.max_strings ?? 20, max_refs_per_string: x.max_refs_per_string ?? 50, max_total_refs: x.max_total_refs ?? 500 }) },
  }, p.op, p)
);

// ── re_module: module / import / export resolution ───────────────────
server.tool(
  "re_module",
  "Resolve module internals. ops: module {name}, export {module_base,export_name}, import {module_base,import_name}",
  { op: z.enum(["module","export","import"]).describe("Operation"),
    name:        z.string().optional().describe("module: module name e.g. 'kernel32.dll'"),
    module_base: z.string().optional().describe("export/import: module base hex address"),
    export_name: z.string().optional().describe("export: exported function name"),
    import_name: z.string().optional().describe("import: imported function name") },
  async (p) => dispatch({
    module: { cmd: "get_module", required: ["name"], build: x => ({ name: x.name }) },
    export: { cmd: "get_export", required: ["module_base","export_name"], hex: ["module_base"], build: x => ({ module_base: x.module_base, export_name: x.export_name }) },
    import: { cmd: "get_import", required: ["module_base","import_name"], hex: ["module_base"], build: x => ({ module_base: x.module_base, import_name: x.import_name }) },
  }, p.op, p)
);

// ── re_disasm: disassembly & function analysis ───────────────────────
server.tool(
  "re_disasm",
  "Disassembly & code analysis. ops: disasm {address,count?,size?,bytes?}, vtable {address,max_entries?,disasm_preview?}, rtti {object_address} (address of an object instance; first qword must be its vtable ptr), gensig {address,length?}, bounds {address}, analyze_fn {address,max_size?}",
  { op: z.enum(["disasm","vtable","rtti","gensig","bounds","analyze_fn"]).describe("Operation"),
    address:   z.string().optional().describe("Target hex address (most ops)"),
    count:     z.number().int().min(1).max(1024).optional().describe("disasm: instruction count (default 10, max 1024)"),
    size:      z.number().int().min(1).max(4096).optional().describe("disasm: max bytes to read (default 256, max 4096)"),
    bytes:     z.boolean().optional().describe("disasm: include per-instruction raw bytes (default false)"),
    max_entries: z.number().int().min(1).max(512).optional().describe("vtable: max entries (default 50, max 512)"),
    disasm_preview: z.boolean().optional().describe("vtable: disasm first insns of each entry (default false)"),
    object_address: z.string().optional().describe("rtti: address of an object instance (its first qword is the vtable pointer)"),
    length:    z.number().int().min(4).max(256).optional().describe("gensig: byte count (default 32, max 256)"),
    max_size:  z.number().int().min(1).max(65536).optional().describe("analyze_fn: max bytes to analyze (default 4096, max 64KB)") },
  async (p) => dispatch({
    disasm:     { cmd: "disassemble",          required: ["address"], hex: ["address"], build: x => ({ address: x.address, count: x.count ?? 10, size: x.size ?? 256, bytes: x.bytes ?? false }) },
    vtable:     { cmd: "analyze_vtable",       timeout: 60000, required: ["address"], hex: ["address"], build: x => ({ address: x.address, max_entries: x.max_entries ?? 50, disasm_preview: x.disasm_preview ?? false }) },
    rtti:       { cmd: "read_rtti",            required: ["object_address"], hex: ["object_address"], build: x => ({ object_address: x.object_address }) },
    gensig:     { cmd: "generate_signature",   required: ["address"], hex: ["address"], build: x => ({ address: x.address, length: x.length ?? 32 }) },
    bounds:     { cmd: "find_function_bounds", timeout: 30000, required: ["address"], hex: ["address"], build: x => ({ address: x.address }) },
    analyze_fn: { cmd: "analyze_function",     timeout: 60000, required: ["address"], hex: ["address"], build: x => ({ address: x.address, max_size: x.max_size ?? 4096 }) },
  }, p.op, p)
);

// ── re_vm: virtual memory ────────────────────────────────────────────
server.tool(
  "re_vm",
  "Virtual memory. ops: vquery {address}, vad {heap_only?,compact?,min_size?,addr_start?,addr_end?,limit?,page_offset?} (compact defaults TRUE; paginated — default limit 500, max 5000; response has has_more/total_matched), alloc {size} (RWX), free {address}",
  { op: z.enum(["vquery","vad","alloc","free"]).describe("Operation"),
    address:   z.string().optional().describe("vquery/free: hex address"),
    heap_only: z.boolean().optional().describe("vad: only heap-likely regions (default false)"),
    compact:   z.boolean().optional().describe("vad: only {start,size} (default TRUE)"),
    min_size:  z.number().int().min(0).optional().describe("vad: skip regions smaller than N bytes"),
    addr_start: z.string().optional().describe("vad: overlap range start hex"),
    addr_end:   z.string().optional().describe("vad: overlap range end hex"),
    limit:      z.number().int().min(1).max(5000).optional().describe("vad: max regions to return (default 500, max 5000)"),
    page_offset: z.number().int().min(0).max(1000000).optional().describe("vad: skip N matching regions before returning"),
    size:      z.number().int().min(1).max(268435456).optional().describe("alloc: bytes to allocate (max 256MB)") },
  async (p) => dispatch({
    vquery: { cmd: "virtual_query",    required: ["address"], hex: ["address"], build: x => ({ address: x.address }) },
    vad:    { cmd: "get_vad_snapshot", timeout: 60000, hex: ["addr_start","addr_end"], build: x => ({ heap_only: x.heap_only ?? false, compact: x.compact ?? true, min_size: x.min_size ?? 0, addr_start: x.addr_start ?? "0x0", addr_end: x.addr_end ?? "0x0", limit: x.limit ?? 500, page_offset: x.page_offset ?? 0 }) },
    alloc:  { cmd: "alloc_vm",         required: ["size"], build: x => ({ size: x.size }) },
    free:   { cmd: "free_vm",          required: ["address"], hex: ["address"], build: x => ({ address: x.address }) },
  }, p.op, p)
);

// ── re_diff: snapshot diff & emulation ───────────────────────────────
server.tool(
  "re_diff",
  "Snapshots & emulation. ops: dump {address,size,label}, diff {label_a,label_b,values?} (returns changed offsets; set values:true for per-byte a/b), emulate {code_address,code_size,entry_offset?,registers?,map_regions?,read_registers?,max_instructions?}",
  { op: z.enum(["dump","diff","emulate"]).describe("Operation"),
    address: z.string().optional().describe("dump: hex address"),
    size:    z.number().int().min(1).max(1048576).optional().describe("dump: size in bytes (max 1MB)"),
    label:   z.string().optional().describe("dump: snapshot label"),
    label_a: z.string().optional().describe("diff: first snapshot label"),
    label_b: z.string().optional().describe("diff: second snapshot label"),
    values:  z.boolean().optional().describe("diff: include per-byte a/b values (default false = offsets only)"),
    code_address: z.string().optional().describe("emulate: addr to read code from"),
    code_size:    z.number().int().min(1).max(1048576).optional().describe("emulate: bytes of code to copy (max 1MB)"),
    entry_offset: z.number().int().min(0).max(1048576).optional().describe("emulate: exec start offset (default 0)"),
    registers:    z.record(z.string(), z.string()).optional().describe("emulate: initial regs as hex strings"),
    map_regions:  z.array(z.object({ address: z.string(), size: z.number().int().min(1).max(16777216) })).max(32).optional().describe("emulate: extra regions to map (max 32 regions, 16MB each)"),
    read_registers: z.array(z.string()).optional().describe("emulate: regs to read after (default ['rax'])"),
    max_instructions: z.number().int().min(1).max(1000000).optional().describe("emulate: max insns (default 10000, max 1M)") },
  async (p) => dispatch({
    dump:    { cmd: "dump_memory_region", required: ["address","size","label"], hex: ["address"], build: x => ({ address: x.address, size: x.size, label: x.label }) },
    diff:    { cmd: "diff_memory",        required: ["label_a","label_b"], build: x => ({ label_a: x.label_a, label_b: x.label_b, values: x.values ?? false }) },
    emulate: { cmd: "emulate_code",       timeout: 60000, required: ["code_address","code_size"], hex: ["code_address"], build: x => {
                 if (x.registers) for (const k of Object.keys(x.registers)) assertHex(x.registers[k], `registers.${k}`);
                 (x.map_regions ?? []).forEach((r: any, i: number) => assertHex(r.address, `map_regions[${i}].address`));
                 return { code_address: x.code_address, code_size: x.code_size, entry_offset: x.entry_offset, registers: x.registers, map_regions: x.map_regions, read_registers_csv: (x.read_registers ?? ["rax"]).join(","), max_instructions: x.max_instructions };
               } },
  }, p.op, p)
);

// ── re_cs2: CS2-specific helpers ─────────────────────────────────────
server.tool(
  "re_cs2",
  "CS2-specific. ops: interface {module_base,interface_name}, schema {filter?,limit?} — ALWAYS pass filter (substring match on field name, e.g. 'C_BaseEntity' or 'm_iHealth'); unfiltered schema is huge. Returns 'name:offset' strings. count=returned, total_matched=all hits.",
  { op: z.enum(["interface","schema"]).describe("Operation"),
    module_base:    z.string().optional().describe("interface: module base hex address"),
    interface_name: z.string().optional().describe("interface: interface name"),
    filter:         z.string().optional().describe("schema: substring filter on field name — required unless all:true"),
    limit:          z.number().int().min(1).max(2000).optional().describe("schema: cap returned entries (default 100, max 2000)"),
    all:            z.boolean().optional().describe("schema: permit unfiltered query — still capped (default limit 100, max 2000), NOT a full dump") },
  async (p) => dispatch({
    interface: { cmd: "cs2_get_interface", required: ["module_base","interface_name"], hex: ["module_base"], build: x => ({ module_base: x.module_base, interface_name: x.interface_name }) },
    schema:    { cmd: "cs2_schema_dump",   timeout: 60000, build: x => {
                   if (!x.filter && !x.all) throw new Error("schema: filter required (or pass all:true)");
                   return { filter: x.filter ?? "", limit: x.limit ?? 100, all: x.all ?? false };
                 } },
  }, p.op, p)
);
// ── Start Server ─────────────────────────────────────────────────────

async function main() {
  // IMPORTANT: connect stdio FIRST so Claude's MCP handshake succeeds immediately.
  // If we set up the WebSocket bridge first and it hangs (EADDRINUSE race with a
  // dying previous instance, TIME_WAIT, etc.), Claude never sees the handshake
  // response and reports "MCP error -32000: Connection closed". Tool calls that
  // arrive before the bridge is ready will return "Perception not connected",
  // which is a clean, recoverable error — not a broken pipe.
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("[perception-mcp] stdio transport connected");

  // Now set up the WS bridge. Run it in the background so startup never blocks
  // on networking. If tryStartHub throws or takes too long, we still survive.
  (async () => {
    try {
      const becameHub = await tryStartHub();
      if (!becameHub) {
        startRelay();
      }
      console.error(`[perception-mcp] Bridge ready (${isHub ? "HUB" : "RELAY"} mode)`);
    } catch (e) {
      console.error("[perception-mcp] Bridge setup failed, falling back to relay:", e);
      try { startRelay(); } catch (e2) { console.error("[perception-mcp] Relay fallback failed:", e2); }
    }
  })();
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
