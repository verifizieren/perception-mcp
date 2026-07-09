# Perception RE MCP Server

MCP server that bridges Claude Code to [Perception.cx](https://perception.cx) reverse engineering tools via AngelScript WebSocket.

```
Claude Code (stdio) → MCP Server (Node.js) ← WebSocket :9001 → re_server.as (Perception IDE)
```

Multiple Claude Code instances can share the same Perception connection simultaneously through a hub/relay architecture.

> **This fork is token-optimized _and_ hardened.** The original exposed 44 individual tools (~9-14k tokens of schema loaded every session), pretty-printed every response, shipped a broken `ptr_chain`, lost precision on 64-bit values, and left long scans with no timeout. This fork collapses the tools into **9 category dispatchers**, minifies responses, fixes those correctness bugs, and adds per-op validation. Same capability, a fraction of the token cost. See [Token Optimizations](#token-optimizations) and [Correctness & Safety](#correctness--safety).

## Prerequisites

- [Node.js](https://nodejs.org/) (v18+)
- [Perception.cx](https://perception.cx) with AngelScript IDE
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI

## Installation

```bash
git clone https://github.com/verifizieren/perception-mcp.git
cd perception-mcp
npm install
npm run build
```

`dist/` is gitignored - you **must** run `npm run build` after cloning or `dist/index.js` won't exist.

## Configuration

### Global (all Claude Code sessions)

Create or edit `~/.mcp.json`:

```json
{
  "mcpServers": {
    "perception-re": {
      "command": "node",
      "args": ["<full-path-to>/perception-mcp/dist/index.js"]
    }
  }
}
```

Replace `<full-path-to>` with the absolute path to where you cloned the repo. Use forward slashes even on Windows.

### Per-project

Add the same config to your project's `.mcp.json` in the project root.

## Usage

### 1. Load the AngelScript server in Perception

Open `re_server.as` in the Perception IDE script editor and run it. The script runs in background mode - it automatically keeps trying to connect to the MCP server and reconnects if disconnected. You can load it on Perception startup.

Waiting:
```
[RE Server] Waiting for MCP server... (attempt 1)
```
Connected:
```
[RE Server] Connected to MCP server.
```

### 2. Start Claude Code

Open Claude Code in any project. The MCP server starts automatically via `~/.mcp.json`.

### 3. Multiple instances

First instance = **hub** (WebSocket server on port 9001). Additional instances auto-connect as **relays** through the hub, sharing the one Perception connection. No extra setup.

## Tools

All functionality is exposed through **9 dispatchers**. Each takes an `op` selector plus the args for that op. This keeps the schema footprint small while covering every operation.

| Dispatcher | ops |
|------------|-----|
| `re_proc`   | `attach` {name?\|pid?}, `detach`, `info`, `is_valid` {address}, `tebs` |
| `re_read`   | `bytes` {address,size}, `values` {address,type,count?}, `string` {address,max_length?}, `wstring` {...}, `ptr_chain` {base,offsets[],final_type?,verbose?}, `struct` {address,fields[]}, `ptr_array` {address,count,offset_delta?}, `hex_dump` {address,size?}, `filter_ptrs` {base,count,vtable_check_addr,stride?,deref_offset?} |
| `re_write`  | `bytes` {address,data}, `values` {address,type,values[]}, `string` {address,text}, `wstring` {address,text} |
| `re_scan`   | `pattern` {signature,...}, `pattern_all` {signature,...,max_results?}, `value` {type,value,heap_only?,page_offset?,page_limit?}, `ptr_to` {target,...}, `heap_regions` {regions[],type,value,max_results?}, `xrefs` {target,...}, `string_refs` {search_text} |
| `re_module` | `module` {name}, `export` {module_base,export_name}, `import` {module_base,import_name} |
| `re_disasm` | `disasm` {address,count?,size?,bytes?}, `vtable` {address,max_entries?,disasm_preview?}, `rtti` {object_address} (object instance; first qword = vtable ptr), `gensig` {address,length?}, `bounds` {address}, `analyze_fn` {address,max_size?} |
| `re_vm`     | `vquery` {address}, `vad` {heap_only?,compact?,min_size?,addr_start?,addr_end?}, `alloc` {size}, `free` {address} |
| `re_diff`   | `dump` {address,size,label}, `diff` {label_a,label_b,values?}, `emulate` {code_address,code_size,...} |
| `re_cs2`    | `interface` {module_base,interface_name}, `schema` {filter\|all,limit?} |

**Value types:** `u8 u16 u32 u64 i8 i16 i32 i64 f32 f64` (plus `string wstring ptr` where noted).

### Notes on defaults

- `re_vm vad` returns compact `{start,size}` by default - pass `compact:false` for protection/heap_likely metadata. Always filter (`min_size`, `heap_only`, `addr_*`) to avoid oversized responses.
- `re_read ptr_chain` returns `final_address`/`final_value` only; pass `verbose:true` for the per-step trace. `u64`/`i64` final values come back as hex strings (JSON numbers can't hold 64 bits).
- `re_read values`/`struct` return `u64`/`i64` as hex strings too; smaller ints as numbers.
- `re_read bytes` caps at 64KB unless you pass `raw:true` (hard max 1MB) — hex payloads balloon fast.
- `re_write values` accepts hex strings (`"0x1122334455667788"`) for exact 64-bit writes; plain numbers still work for small types.
- `re_diff diff` returns changed offsets only; pass `values:true` for per-byte a/b. Flags `truncated:true` at 1000 diffs.
- `re_cs2 schema` — `filter` is **required** (substring on field name) unless you pass `all:true`; default `limit` 100, max 2000. Returns `name:offset` strings.
- `re_scan value`/`ptr_to` default `page_limit` is 100; `count` reflects the true total, `has_more` flags more pages. Heavy scans have a **caller-side** 120s timeout — the MCP request rejects on timeout, but Perception's scan loop is not cancelled and keeps running until it finishes.

## Example

```
You: attach to cs2.exe and show me the first 10 instructions at its entry point

Claude: [re_proc op:attach name:"cs2.exe"] [re_module op:module name:"client.dll"] [re_disasm op:disasm ...]
```

## Token Optimizations

This fork's changes vs upstream:

- **44 tools -> 9 dispatchers.** ~80% less tool-schema loaded into context per session.
- **Minified responses.** Dropped 2-space pretty-printing across all ops.
- **`re_cs2 schema`** - added substring `filter` + `limit`, flattened `{name,offset}` dicts to `name:offset` strings.
- **`re_disasm vtable`** - dropped derivable `index`/`address`; flat function-pointer array unless `disasm_preview`.
- **`re_disasm disasm` / `analyze_fn`** - dropped `mnemonic` (redundant with `text`); `bytes` now opt-in on `disasm`.
- **`re_read values` / `struct`** - dropped per-element `address` (derivable from base + offset/stride); `base` emitted once.
- **`re_read ptr_chain`** - per-step trace gated behind `verbose`.
- **`re_diff diff`** - offsets-only by default; `values` flag restores byte values.
- **`re_scan value`/`ptr_to`** - page defaults lowered (1000 -> 100), true `count` retained.
- **Perf:** removed a redundant double memory read in `re_read values`, and dead per-instruction dictionary lookups in disassembly.

No capability was removed - everything trimmed is either derivable by the model or opt-in behind a flag.

## Correctness & Safety

This fork also fixes real bugs and hardens the bridge:

- **`ptr_chain` fixed.** Every call previously died with `missing offsets array` — the handler required an `offsets` array the MCP never sent (it sends `offsets_csv`). Rewritten to use `offsets_csv`, and `final_type` now handles the full `i8/i16/i64` set (was silently falling through to a pointer read).
- **64-bit integers no longer lose precision.** `u64`/`i64` reads (`values`, `struct`, `ptr_chain`) return hex strings; `u64`/`i64` writes parse from hex/decimal strings instead of round-tripping through a `double` (which mangled anything above 2^53).
- **Per-op validation.** Missing required fields and malformed hex are rejected locally in the MCP layer, so bad calls fail instantly instead of turning into reads/writes at `0x0` or empty scans.
- **Caller-side timeouts.** Every long op (`pattern_all`, `value`, `ptr_to`, `xrefs`, `string_refs`, `vtable`, `analyze_fn`, `schema`) rejects the MCP request after 30–120s so it doesn't hang forever if Perception stalls. Note: this doesn't cancel the AngelScript scan loop — it keeps running to completion, the caller just stops waiting. See Known limitations.
- **Output caps.** `read bytes` >64KB needs `raw:true`; `ptr_array` count capped at 4096; `diff` flags `truncated`; `cs2 schema` requires a filter (or `all:true`) with a default limit.
- **`emulate` honors `read_registers`** (defaults to `rax` only) instead of always dumping 9 registers.
- **`find_xrefs`** caps on in-region matches, not raw scan index — it no longer drops valid refs past the first 500.
- **Removed dead `assemble` op** (it only ever returned an error) and the unhonorable `module_name` arg on `string_refs` (whole-process scan has no region param).

## Security

- **The WebSocket hub binds `127.0.0.1` only** (`host: "127.0.0.1"` on the `WebSocketServer`) — no LAN exposure. Previous versions omitted `host` and bound the unspecified interface, meaning anyone on your network could write process memory and allocate RWX. Fixed.
- **Relay clients must present a per-user shared token.** On first hub launch, a 32-byte random token is written to `%TEMP%/perception-mcp-<user>.token` mode 0600. Any relay MCP instance reads it and passes it in the `_mcp_relay` handshake; a wrong or missing token drops the socket with WS close code 1008.
- **Perception AngelScript hello is accepted without a token** — the AS runtime here has no file I/O primitives exposed, so requiring a token file would break attachment. Loopback bind is the primary defense on that path; a local process running as the same user can still impersonate. Delete the token file to rotate.
- **Handshake timeout is 2 seconds.** Sockets that don't identify with either `_mcp_relay` or `_mcp_perception`/`_perception_hello` are dropped.

## Known limitations (not yet addressed)

Static review flagged these; they need in-Perception runtime testing before changing, so they're documented rather than blindly patched:

- **Node request timeouts are caller-side only.** A 120s timeout rejects the pending MCP request, but the AngelScript scan loop (`scan_value`, `pattern_scan_all`, `find_xrefs`, `find_string_refs`, `cs2_schema_dump`) does not check a deadline and keeps running until it finishes. Cooperative cancellation would need to be added inside those loops.
- **`re_diff emulate` maps code at a fixed base (0x10000), not the original VA.** RIP-relative operands resolve against that base, so snippets that reference absolute module data may emulate inaccurately. Map the needed data via `map_regions`, or treat results as position-independent only.
- **`re_scan pattern`/`xrefs` scan cost isn't bounded by `max_results`/pagination** — those cap returned results, not work done. Absolute-xref scanning is process-wide, then filtered to the region. Pass `module_name` or `start`+`size` to bound it.
- **`xrefs` relative-ref detection is heuristic** (rel32 pattern match, instruction start guessed as one byte prior). It can misreport; verify hits by disassembling around them.
- **`gensig` wildcarding is heuristic** (operand-tail bytes). Confirm uniqueness with `pattern_all`.
- **`scan heap_regions`** now chunks every region regardless of size (16MB windows, 8-byte overlap so alignment-8 values straddling a chunk are still caught). A total-bytes budget (default 4GB, max 16GB via `max_total_bytes`) prevents runaway scans; if hit, `budget_exceeded:true` and results are partial. Pass `alignment:1` to catch unaligned values (4-8x slower).

**MCP not showing in Claude Code** - verify the absolute path to `dist/index.js` in `~/.mcp.json`, restart Claude Code, run `npm run build` if `dist/` is missing.

**AngelScript "Waiting for MCP server..."** - normal; it polls until Claude Code starts.

**Second instance can't use tools** - relay auto-retries every 3s; ensure the first (hub) instance is running.

**Port 9001 in use** - the hub can't bind if something else holds the port; free it or kill the stale process.

**Perception disconnected** - the AngelScript server auto-reconnects; if Perception itself closed, reopen and reload `re_server.as`.

## Project Structure

```
perception-mcp/
├── src/
│   └── index.ts          # MCP server + WebSocket hub/relay bridge + 9 dispatchers
├── re_server.as          # AngelScript server for Perception IDE
├── package.json
├── tsconfig.json
└── dist/                 # Built output (gitignored)
    └── index.js
```

## API Reference

Perception AngelScript API: https://docs.perception.cx/perception-angel-script-api/
