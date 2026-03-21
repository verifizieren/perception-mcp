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

Open `re_server.as` in the Perception IDE script editor and run it. The script runs in background mode — it will automatically keep trying to connect to the MCP server and reconnect if disconnected. You can load it on Perception startup.

Console output when waiting:
```
[RE Server] Starting Perception RE server (background mode)...
[RE Server] Waiting for MCP server... (attempt 1)
```

Console output when connected:
```
[RE Server] Connected to MCP server. 35+ RE tools available.
```

### 2. Start Claude Code

Open Claude Code in any project. The MCP server starts automatically via the config in `~/.mcp.json`. Once both sides are running, you can use all 35+ RE tools directly from Claude.

### 3. Multiple instances

The first Claude Code instance starts as a **hub** (WebSocket server on port 9001). Additional instances automatically connect as **relays** through the hub. All instances share the same Perception connection — no extra setup needed.

## Available Tools (35+)

### Process Management
| Tool | Description |
|------|-------------|
| `attach_process` | Attach to a process by name or PID |
| `detach_process` | Detach from current process |
| `process_info` | Get PID, base address, PEB, alive status |
| `is_valid_address` | Check if an address is valid |

### Memory Reading
| Tool | Description |
|------|-------------|
| `read_memory` | Read raw hex bytes |
| `read_values` | Read typed values (u8/u16/u32/u64/i8-i64/f32/f64) |
| `read_string` | Read ANSI/UTF-8 string |
| `read_wstring` | Read UTF-16 wide string |
| `read_pointer_chain` | Follow pointer chain through offsets |
| `read_struct` | Read structured fields with offset/type definitions |
| `read_pointer_array` | Read array of pointers |
| `hex_dump` | Traditional hex + ASCII dump |

### Memory Writing
| Tool | Description |
|------|-------------|
| `write_memory` | Write raw hex bytes |
| `write_values` | Write typed values |
| `write_string` | Write ANSI string (null-terminated) |
| `write_wstring` | Write UTF-16 string (null-terminated) |

### Pattern Scanning
| Tool | Description |
|------|-------------|
| `pattern_scan` | IDA-style signature scan (first match) |
| `pattern_scan_all` | IDA-style signature scan (all matches) |

### Module Info
| Tool | Description |
|------|-------------|
| `get_module` | Get module base address + size |
| `get_export` | Resolve exported function address |
| `get_import` | Resolve IAT entry address |

### Disassembly & Assembly
| Tool | Description |
|------|-------------|
| `disassemble` | Zydis disassembly at address |
| `assemble` | Instruction encoding |

### Virtual Memory
| Tool | Description |
|------|-------------|
| `virtual_query` | Query memory region info |
| `get_vad_snapshot` | List all VAD entries |
| `alloc_vm` | Allocate RWX memory in target |
| `free_vm` | Free allocated memory |

### Scanning
| Tool | Description |
|------|-------------|
| `scan_value` | Full-process value scan (u32/u64/float/double/string/wstring/pointer) |
| `scan_pointer_to` | Find all pointers to an address |

### Advanced RE
| Tool | Description |
|------|-------------|
| `find_xrefs` | Find cross-references (relative + absolute) |
| `analyze_vtable` | Read vtable entries with optional disassembly preview |
| `read_rtti` | Read MSVC RTTI class name + hierarchy |
| `generate_signature` | Auto-generate IDA-style signature from code |
| `find_function_bounds` | Find function start/end boundaries |
| `analyze_function` | Full function disassembly with call/jump analysis |
| `find_string_refs` | Find code references to strings |

### Memory Diff
| Tool | Description |
|------|-------------|
| `dump_memory_region` | Snapshot memory for diffing |
| `diff_memory` | Compare two snapshots |

### Emulation
| Tool | Description |
|------|-------------|
| `emulate_code` | Unicorn x86_64 emulation with register I/O and memory mapping |

### Threads
| Tool | Description |
|------|-------------|
| `get_tebs` | Get all Thread Environment Block addresses |

### CS2 Specific
| Tool | Description |
|------|-------------|
| `cs2_get_interface` | Resolve Source 2 interface pointer |
| `cs2_schema_dump` | Dump schema system classes and offsets |

## Example

```
You: attach to chrome.exe and show me the first 10 instructions at its entry point

Claude: [uses attach_process, get_module, disassemble]
```

## Troubleshooting

**MCP not showing up in Claude Code**
- Verify `~/.mcp.json` has the correct absolute path to `dist/index.js`
- Restart Claude Code after editing the config
- Run `npm run build` if `dist/` doesn't exist

**AngelScript "Waiting for MCP server..."**
- This is normal — the script polls in the background until Claude Code starts
- Once you open Claude Code, it connects automatically

**Second Claude Code instance can't use tools**
- The relay auto-retries every 3 seconds, give it a moment
- Check that the first instance (hub) is still running

**Perception disconnected**
- The AngelScript server auto-reconnects when the MCP becomes available again
- If Perception itself was closed, reopen it and reload `re_server.as`

## Project Structure

```
perception-mcp/
├── src/
│   └── index.ts          # MCP server + WebSocket hub/relay bridge
├── re_server.as          # AngelScript server for Perception IDE
├── package.json
├── tsconfig.json
└── dist/                 # Built output (gitignored)
    └── index.js
```

## API Reference

For Perception's AngelScript API documentation, see:
https://docs.perception.cx/perception-angel-script-api/
