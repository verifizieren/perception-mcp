# Perception RE MCP Server

MCP server that bridges Claude Code to [Perception.cx](https://perception.cx) reverse engineering tools via AngelScript WebSocket.

```
Claude Code (stdio) → MCP Server (Node.js) ← WebSocket :9001 → re_server.as (Perception IDE)
```

Multiple Claude Code instances can share the same Perception connection simultaneously through a hub/relay architecture.

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

All functionality is exposed through **10 dispatchers**. Each takes an `op` selector plus the args for that op. This keeps the schema footprint small while covering every operation.

| Dispatcher | ops |
|------------|-----|
| `re_proc`   | `status` (Perception connected? — no attach needed), `attach` {name?\|pid?}, `detach`, `info`, `is_valid` {address}, `tebs` |
| `re_session` | `get`, `save_offset` {name,value,module?,notes?}, `save_signature` {name,pattern,result?}, `save_struct` {name,fields}, `note` {text}, `clear` {target?} — local JSON scratchpad, survives restarts |
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

- `re_proc status` reports connection state from the bridge itself (no round-trip to Perception), so it answers even when Perception is down — call it before attaching instead of guessing.
- `re_session` persists confirmed offsets/sigs/structs/notes to `%TEMP%/perception-mcp-session-<user>.json`. Call `re_session get` at task start so prior findings are reused instead of re-scanned; `re_session clear` when switching target.
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
