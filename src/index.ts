import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { WebSocketServer, WebSocket } from "ws";

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
let pendingRequests = new Map<string, { resolve: (v: any) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();
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
    const wss = new WebSocketServer({ port: WS_PORT });

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

    // First message determines client type
    const identifyTimeout = setTimeout(() => {
      if (clientType === "unknown") {
        clientType = "perception";
        percClient = ws;
        console.error("[perception-mcp] Perception AngelScript client connected");
      }
    }, 2000);

    ws.on("message", (data) => {
      try {
        const msg = JSON.parse(data.toString());

        // Handshake from relay client
        if (clientType === "unknown" && msg._mcp_relay) {
          clearTimeout(identifyTimeout);
          clientType = "relay";
          relayId = msg._instance_id || `relay_${Date.now()}`;
          relayClients.set(relayId, ws);
          console.error(`[perception-mcp] Relay MCP instance connected: ${relayId}`);
          ws.send(JSON.stringify({ _mcp_relay_ack: true }));
          return;
        }

        // If unknown and not a relay handshake, it's Perception
        if (clientType === "unknown") {
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
        percClient = null;
        // Reject all pending requests
        for (const [id, pending] of pendingRequests) {
          clearTimeout(pending.timer);
          pending.reject(new Error("Perception client disconnected"));
        }
        pendingRequests.clear();
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
    ws.send(JSON.stringify({ _mcp_relay: true, _instance_id: instanceId }));
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
      const timer = setTimeout(() => {
        pendingRequests.delete(id);
        reject(new Error(`Request timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      pendingRequests.set(id, { resolve, reject, timer });
      percClient.send(JSON.stringify({ _id: id, cmd, ...params }));
    }
    // Relay mode: send through hub
    else {
      if (!hubConnection || hubConnection.readyState !== WebSocket.OPEN) {
        return reject(new Error("Not connected to hub. Is the first Claude Code instance still running?"));
      }
      const id = `${instanceId}_req_${++requestId}`;
      const timer = setTimeout(() => {
        pendingRequests.delete(id);
        reject(new Error(`Request timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      pendingRequests.set(id, { resolve, reject, timer });
      hubConnection.send(JSON.stringify({ _id: id, cmd, ...params }));
    }
  });
}

async function callTool(cmd: string, params: Record<string, any> = {}, timeoutMs = 30000): Promise<string> {
  const result = await sendCommand(cmd, params, timeoutMs);
  if (result.error) throw new Error(result.error);
  return JSON.stringify(result, null, 2);
}

// ─── MCP Server ──────────────────────────────────────────────────────
const server = new McpServer({
  name: "perception-re",
  version: "1.0.0",
});

// ── Process Management ───────────────────────────────────────────────

server.tool(
  "attach_process",
  "Attach to a target process by name or PID for memory inspection",
  { name: z.string().optional().describe("Process name (e.g. 'notepad.exe')"),
    pid: z.number().optional().describe("Process ID") },
  async (params) => {
    const res = await callTool("attach", { name: params.name, pid: params.pid });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "detach_process",
  "Detach from the currently attached process",
  {},
  async () => {
    const res = await callTool("detach");
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "process_info",
  "Get info about the currently attached process (PID, base address, PEB, alive status)",
  {},
  async () => {
    const res = await callTool("process_info");
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "is_valid_address",
  "Check if an address is valid in the target process",
  { address: z.string().describe("Hex address (e.g. '0x7FF600000000')") },
  async (params) => {
    const res = await callTool("is_valid_address", { address: params.address });
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Memory Reading ───────────────────────────────────────────────────

server.tool(
  "read_memory",
  "Read raw bytes from process memory. Returns hex-encoded data.",
  { address: z.string().describe("Hex address"),
    size: z.number().describe("Number of bytes to read (max 1MB)") },
  async (params) => {
    const res = await callTool("read_memory", { address: params.address, size: params.size });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "read_values",
  "Read typed values from memory. Types: u8, u16, u32, u64, i8, i16, i32, i64, f32, f64",
  { address: z.string().describe("Hex address"),
    type: z.enum(["u8","u16","u32","u64","i8","i16","i32","i64","f32","f64"]).describe("Value type"),
    count: z.number().optional().describe("Number of consecutive values (default 1)") },
  async (params) => {
    const res = await callTool("read_values", { address: params.address, type: params.type, count: params.count ?? 1 });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "read_string",
  "Read an ANSI/UTF-8 string from memory",
  { address: z.string().describe("Hex address"),
    max_length: z.number().optional().describe("Max chars to read (default 256)") },
  async (params) => {
    const res = await callTool("read_string", { address: params.address, max_length: params.max_length ?? 256 });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "read_wstring",
  "Read a UTF-16 (wide) string from memory",
  { address: z.string().describe("Hex address"),
    max_length: z.number().optional().describe("Max chars to read (default 256)") },
  async (params) => {
    const res = await callTool("read_wstring", { address: params.address, max_length: params.max_length ?? 256 });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "read_pointer_chain",
  "Follow a chain of pointers from a base address through a series of offsets. Returns the final address and value.",
  { base: z.string().describe("Starting hex address"),
    offsets: z.array(z.string()).describe("Array of hex offsets to follow (e.g. ['0x308', '0x330'])"),
    final_type: z.enum(["u8","u16","u32","u64","i8","i16","i32","i64","f32","f64","ptr"]).optional().describe("Type to read at final address (default ptr)") },
  async (params) => {
    const res = await callTool("read_pointer_chain", { base: params.base, offsets_csv: params.offsets.join(","), final_type: params.final_type ?? "ptr" });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "read_struct",
  "Read a structured set of fields from memory. Define fields with offset, type, and name.",
  { address: z.string().describe("Base hex address"),
    fields: z.array(z.object({
      name: z.string().describe("Field name"),
      offset: z.string().describe("Hex offset from base"),
      type: z.enum(["u8","u16","u32","u64","i8","i16","i32","i64","f32","f64","string","wstring","ptr"]).describe("Field type"),
      max_chars: z.number().optional().describe("Max chars for string types")
    })).describe("Array of field descriptors") },
  async (params) => {
    const res = await callTool("read_struct", { address: params.address, fields_json: JSON.stringify(params.fields) });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "read_pointer_array",
  "Read an array of pointers from memory",
  { address: z.string().describe("Base hex address"),
    count: z.number().describe("Number of pointers"),
    offset_delta: z.number().optional().describe("Offset added to each pointer (default 0)") },
  async (params) => {
    const res = await callTool("read_pointer_array", { address: params.address, count: params.count, offset_delta: params.offset_delta ?? 0 });
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Memory Writing ───────────────────────────────────────────────────

server.tool(
  "write_memory",
  "Write raw hex bytes to process memory",
  { address: z.string().describe("Hex address"),
    data: z.string().describe("Hex-encoded bytes to write") },
  async (params) => {
    const res = await callTool("write_memory", { address: params.address, data: params.data });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "write_values",
  "Write typed values to memory",
  { address: z.string().describe("Hex address"),
    type: z.enum(["u8","u16","u32","u64","i8","i16","i32","i64","f32","f64"]).describe("Value type"),
    values: z.array(z.number()).describe("Values to write") },
  async (params) => {
    const res = await callTool("write_values", { address: params.address, type: params.type, values_csv: params.values.join(",") });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "write_string",
  "Write an ANSI string to memory (null-terminated)",
  { address: z.string().describe("Hex address"),
    text: z.string().describe("String to write") },
  async (params) => {
    const res = await callTool("write_string", { address: params.address, text: params.text });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "write_wstring",
  "Write a UTF-16 wide string to memory (null-terminated)",
  { address: z.string().describe("Hex address"),
    text: z.string().describe("String to write") },
  async (params) => {
    const res = await callTool("write_wstring", { address: params.address, text: params.text });
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Pattern Scanning ─────────────────────────────────────────────────

server.tool(
  "pattern_scan",
  "Search for an IDA-style byte pattern in process memory. Returns first match address.",
  { signature: z.string().describe("IDA-style pattern (e.g. '48 8B ?? ?? ?? 89')"),
    start: z.string().optional().describe("Start hex address (default: module base)"),
    size: z.string().optional().describe("Search region size in hex (default: module size)"),
    module_name: z.string().optional().describe("Module to scan (default: main module)") },
  async (params) => {
    const res = await callTool("pattern_scan", params);
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "pattern_scan_all",
  "Search for ALL occurrences of an IDA-style byte pattern",
  { signature: z.string().describe("IDA-style pattern"),
    start: z.string().optional().describe("Start hex address"),
    size: z.string().optional().describe("Search region size in hex"),
    module_name: z.string().optional().describe("Module to scan"),
    max_results: z.number().optional().describe("Cap on matches returned (default 500, max 5000). count field always reflects the true total.") },
  async (params) => {
    const res = await callTool("pattern_scan_all", params, 60000);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Module Info ──────────────────────────────────────────────────────

server.tool(
  "get_module",
  "Get a module's base address and size",
  { name: z.string().describe("Module name (e.g. 'kernel32.dll', 'TslGame.exe')") },
  async (params) => {
    const res = await callTool("get_module", { name: params.name });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "get_export",
  "Resolve an exported function address from a module",
  { module_base: z.string().describe("Module base hex address"),
    export_name: z.string().describe("Export name (e.g. 'NtQueryInformationProcess')") },
  async (params) => {
    const res = await callTool("get_export", params);
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "get_import",
  "Resolve an import's IAT entry address in a module",
  { module_base: z.string().describe("Module base hex address"),
    import_name: z.string().describe("Import function name") },
  async (params) => {
    const res = await callTool("get_import", params);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Disassembly ──────────────────────────────────────────────────────

server.tool(
  "disassemble",
  "Disassemble instructions at a memory address using Zydis. Returns mnemonic, operands, bytes.",
  { address: z.string().describe("Hex address to disassemble at"),
    count: z.number().optional().describe("Number of instructions (default 10)"),
    size: z.number().optional().describe("Max bytes to read (default 256)") },
  async (params) => {
    const res = await callTool("disassemble", { address: params.address, count: params.count ?? 10, size: params.size ?? 256 });
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Virtual Memory Analysis ──────────────────────────────────────────

server.tool(
  "virtual_query",
  "Query virtual memory region info for an address (base, size, protection, heap likelihood)",
  { address: z.string().describe("Hex address to query") },
  async (params) => {
    const res = await callTool("virtual_query", { address: params.address });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "get_vad_snapshot",
  "Get a snapshot of VAD (Virtual Address Descriptor) entries. Use filters to avoid the 210k+ character response that blows the result size limit.",
  { heap_only:   z.boolean().optional().describe("Only return heap-likely regions (default false)"),
    compact:     z.boolean().optional().describe("Return only {start, size} — omit protection/heap_likely metadata (default false)"),
    min_size:    z.number().optional().describe("Skip regions smaller than this many bytes (e.g. 65536)"),
    addr_start:  z.string().optional().describe("Only include regions that overlap this hex address range start"),
    addr_end:    z.string().optional().describe("Only include regions that overlap this hex address range end") },
  async (params) => {
    const res = await callTool("get_vad_snapshot", {
      heap_only:  params.heap_only  ?? false,
      compact:    params.compact    ?? false,
      min_size:   params.min_size   ?? 0,
      addr_start: params.addr_start ?? "0x0",
      addr_end:   params.addr_end   ?? "0x0",
    }, 60000);
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "alloc_vm",
  "Allocate RWX virtual memory in the target process",
  { size: z.number().describe("Size in bytes to allocate") },
  async (params) => {
    const res = await callTool("alloc_vm", { size: params.size });
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "free_vm",
  "Free previously allocated virtual memory in the target process",
  { address: z.string().describe("Hex address to free") },
  async (params) => {
    const res = await callTool("free_vm", { address: params.address });
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Thread Info ──────────────────────────────────────────────────────

server.tool(
  "get_tebs",
  "Get all Thread Environment Block (TEB) addresses for the target process",
  {},
  async () => {
    const res = await callTool("get_tebs");
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Value Scanning ───────────────────────────────────────────────────

server.tool(
  "scan_value",
  "Scan entire process memory for a specific value. Returns array of addresses where value was found. Use page_offset/page_limit to paginate when count is large.",
  { type: z.enum(["u32","u64","float","double","string","wstring","pointer"]).describe("Value type to scan for"),
    value: z.union([z.string(), z.number()]).describe("Value to search for (hex string for u64/pointer, number for u32/float/double)"),
    heap_only:   z.boolean().optional().describe("Only scan heap regions (default false)"),
    page_offset: z.number().optional().describe("Skip this many results before returning (default 0)"),
    page_limit:  z.number().optional().describe("Max addresses to return (default 1000, max 5000)") },
  async (params) => {
    const res = await callTool("scan_value", params, 120000);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Advanced RE: Cross-references ────────────────────────────────────

server.tool(
  "find_xrefs",
  "Find cross-references to a target address within a memory region. Searches for relative offsets and absolute pointers.",
  { target: z.string().describe("Target hex address to find references to"),
    start: z.string().optional().describe("Search region start (default: module base)"),
    size: z.string().optional().describe("Search region size in hex"),
    module_name: z.string().optional().describe("Module to search in") },
  async (params) => {
    const res = await callTool("find_xrefs", params, 60000);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Advanced RE: VTable Analysis ─────────────────────────────────────

server.tool(
  "analyze_vtable",
  "Read and analyze a virtual function table. Returns array of function pointers with optional disassembly of each entry.",
  { address: z.string().describe("VTable address (pointer to first function pointer)"),
    max_entries: z.number().optional().describe("Max entries to read (default 50)"),
    disasm_preview: z.boolean().optional().describe("Disassemble first few instructions of each entry (default false)") },
  async (params) => {
    const res = await callTool("analyze_vtable", { address: params.address, max_entries: params.max_entries ?? 50, disasm_preview: params.disasm_preview ?? false }, 60000);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Advanced RE: RTTI ────────────────────────────────────────────────

server.tool(
  "read_rtti",
  "Read MSVC Run-Time Type Information from an object's vtable pointer. Returns class name and hierarchy.",
  { vtable_address: z.string().describe("Address of the vtable pointer (object's first qword)") },
  async (params) => {
    const res = await callTool("read_rtti", params);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Advanced RE: Signature Generation ────────────────────────────────

server.tool(
  "generate_signature",
  "Generate an IDA-style byte signature from code at an address, wildcarding relocatable parts.",
  { address: z.string().describe("Hex address to generate signature from"),
    length: z.number().optional().describe("Number of bytes (default 32)") },
  async (params) => {
    const res = await callTool("generate_signature", { address: params.address, length: params.length ?? 32 });
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Advanced RE: Function Analysis ───────────────────────────────────

server.tool(
  "find_function_bounds",
  "Attempt to find the start and end of a function containing the given address",
  { address: z.string().describe("Hex address within a function") },
  async (params) => {
    const res = await callTool("find_function_bounds", params, 30000);
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "analyze_function",
  "Disassemble and analyze an entire function. Returns all instructions, basic blocks, and call targets.",
  { address: z.string().describe("Function start address"),
    max_size: z.number().optional().describe("Max bytes to analyze (default 4096)") },
  async (params) => {
    const res = await callTool("analyze_function", { address: params.address, max_size: params.max_size ?? 4096 }, 60000);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Advanced RE: Memory Diff ─────────────────────────────────────────

server.tool(
  "dump_memory_region",
  "Dump a memory region for comparison. Stores snapshot internally for diff_memory.",
  { address: z.string().describe("Hex address"),
    size: z.number().describe("Size in bytes"),
    label: z.string().describe("Label for this snapshot") },
  async (params) => {
    const res = await callTool("dump_memory_region", params);
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "diff_memory",
  "Compare two memory snapshots (taken with dump_memory_region) and show differences",
  { label_a: z.string().describe("First snapshot label"),
    label_b: z.string().describe("Second snapshot label") },
  async (params) => {
    const res = await callTool("diff_memory", params);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Advanced RE: Pointer Scan ────────────────────────────────────────

server.tool(
  "scan_pointer_to",
  "Scan for pointers pointing to a target address. Use page_offset/page_limit to paginate large result sets.",
  { target: z.string().describe("Target hex address"),
    heap_only:   z.boolean().optional().describe("Only scan heap regions (default false)"),
    page_offset: z.number().optional().describe("Skip this many results before returning (default 0)"),
    page_limit:  z.number().optional().describe("Max addresses to return (default 1000, max 5000)") },
  async (params) => {
    const res = await callTool("scan_pointer_to", params, 120000);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Advanced RE: String References ───────────────────────────────────

server.tool(
  "find_string_refs",
  "Search for references to strings in code. Finds LEA instructions loading string addresses.",
  { search_text: z.string().describe("Text to search for in strings"),
    module_name: z.string().optional().describe("Module to search (default: main)") },
  async (params) => {
    const res = await callTool("find_string_refs", params, 60000);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Unicorn Emulation ────────────────────────────────────────────────

server.tool(
  "emulate_code",
  "Emulate x86_64 code using Unicorn engine. Map memory, set registers, run code, read results.",
  { code_address: z.string().describe("Address to read code from (in target process)"),
    code_size: z.number().describe("Size of code to copy"),
    entry_offset: z.number().optional().describe("Offset within code to start execution (default 0)"),
    registers: z.record(z.string(), z.string()).optional().describe("Initial register values as hex strings (e.g. {\"rcx\": \"0x1234\", \"rdx\": \"0x5678\"})"),
    map_regions: z.array(z.object({
      address: z.string().describe("Hex address"),
      size: z.number().describe("Region size")
    })).optional().describe("Additional memory regions to map from target process"),
    read_registers: z.array(z.string()).optional().describe("Registers to read after emulation (default: ['rax'])"),
    max_instructions: z.number().optional().describe("Max instructions to execute (default 10000)") },
  async (params) => {
    const res = await callTool("emulate_code", params, 30000);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Encode / Assemble ────────────────────────────────────────────────

server.tool(
  "assemble",
  "Assemble x86_64 instructions using Zydis encoder. Returns hex bytes.",
  { instructions: z.array(z.object({
      mnemonic: z.string().describe("Instruction mnemonic (e.g. 'MOV', 'NOP', 'RET')"),
      operands: z.array(z.object({
        type: z.enum(["reg","imm","mem"]).describe("Operand type"),
        value: z.string().describe("For reg: register name, for imm: hex value, for mem: 'base+index*scale+disp'")
      })).optional()
    })).describe("Instructions to assemble"),
    base_address: z.string().optional().describe("Base address for relative calculations (default 0)") },
  async (params) => {
    const res = await callTool("assemble", params);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Hex Dump ─────────────────────────────────────────────────────────

server.tool(
  "hex_dump",
  "Read memory and format as a traditional hex dump with ASCII display",
  { address: z.string().describe("Hex address"),
    size: z.number().optional().describe("Number of bytes (default 256, max 4096)") },
  async (params) => {
    const res = await callTool("hex_dump", { address: params.address, size: params.size ?? 256 });
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Targeted Heap Region Scan ─────────────────────────────────────────

server.tool(
  "scan_heap_regions",
  "Scan a caller-supplied list of heap regions for a value via direct memory reads. More targeted than full-process scan_value. Build the region list from get_vad_snapshot with heap_only+compact+min_size filters.",
  { regions: z.array(z.object({
      start: z.string().describe("Hex start address of region"),
      size:  z.string().describe("Hex size of region")
    })).describe("Regions to scan — take from get_vad_snapshot output"),
    type:        z.enum(["u32","u64","pointer"]).describe("Value type (u32=4-byte, u64/pointer=8-byte)"),
    value:       z.union([z.string(), z.number()]).describe("Value to scan for (hex string for u64/pointer, number for u32)"),
    max_results: z.number().optional().describe("Max addresses to return (default 100)") },
  async (params) => {
    const regionsCsv = params.regions.map(r => `${r.start}:${r.size}`).join(",");
    const res = await callTool("scan_heap_regions", {
      regions_csv: regionsCsv,
      type:        params.type,
      value:       params.value,
      max_results: params.max_results ?? 100,
    }, 120000);
    return { content: [{ type: "text", text: res }] };
  }
);

// ── Read & Filter Pointer Array ───────────────────────────────────────

server.tool(
  "read_and_filter_pointers",
  "Read count pointers at base+i*stride, dereference each at deref_offset, and return only those where the dereferenced value equals vtable_check_addr. Replaces a manual loop of read_values + vtable checks.",
  { base:             z.string().describe("Base hex address of the pointer array"),
    count:            z.number().describe("Number of pointers to read"),
    stride:           z.number().optional().describe("Stride between pointers in bytes (default 8)"),
    vtable_check_addr: z.string().describe("Hex address that *ptr+deref_offset must equal"),
    deref_offset:     z.number().optional().describe("Byte offset within the dereferenced object to read and compare (default 0 = vtable)") },
  async (params) => {
    const res = await callTool("read_and_filter_pointers", {
      base:             params.base,
      count:            params.count,
      stride:           params.stride ?? 8,
      vtable_check_addr: params.vtable_check_addr,
      deref_offset:     params.deref_offset ?? 0,
    });
    return { content: [{ type: "text", text: res }] };
  }
);

// ── CS2 Specific ─────────────────────────────────────────────────────

server.tool(
  "cs2_get_interface",
  "Get a CS2 interface pointer by name from a module",
  { module_base: z.string().describe("Module base hex address"),
    interface_name: z.string().describe("Interface name") },
  async (params) => {
    const res = await callTool("cs2_get_interface", params);
    return { content: [{ type: "text", text: res }] };
  }
);

server.tool(
  "cs2_schema_dump",
  "Dump CS2 schema system (all classes and field offsets)",
  {},
  async () => {
    const res = await callTool("cs2_schema_dump", {}, 60000);
    return { content: [{ type: "text", text: res }] };
  }
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
