// ═══════════════════════════════════════════════════════════════════════
// Perception RE Server - AngelScript WebSocket bridge for MCP
// Handles all reverse engineering commands from the MCP server
// ═══════════════════════════════════════════════════════════════════════

ws_t   g_ws;
proc_t g_proc;
bool   g_attached = false;
int    g_callback_id = 0;
bool   g_connected = false;
int    g_retry_count = 0;

// Memory snapshots for diff
dictionary g_snapshots;

// ─── Helpers ─────────────────────────────────────────────────────────

const string HEX_CHARS = "0123456789abcdef";
const string HEX_UPPER = "0123456789ABCDEF";
const string ASCII_PRINTABLE = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

uint64 parse_hex(const string &in s)
{
    string h = s;
    if (h.length() > 2 && (h.substr(0, 2) == "0x" || h.substr(0, 2) == "0X"))
        h = h.substr(2);
    uint64 result = 0;
    for (uint i = 0; i < h.length(); i++)
    {
        result <<= 4;
        uint8 c = h[i];
        if (c >= 48 && c <= 57)       result |= (c - 48);       // 0-9
        else if (c >= 65 && c <= 70)   result |= (c - 55);       // A-F
        else if (c >= 97 && c <= 102)  result |= (c - 87);       // a-f
    }
    return result;
}

string to_hex(uint64 v)
{
    if (v == 0) return "0x0";
    string result = "";
    uint64 tmp = v;
    while (tmp > 0)
    {
        uint8 nibble = uint8(tmp & 0xF);
        result = HEX_CHARS.substr(nibble, 1) + result;
        tmp >>= 4;
    }
    return "0x" + result;
}

// Manual string split since .split() may not be registered
array<string> str_split(const string &in s, const string &in delim)
{
    array<string> parts;
    uint start = 0;
    while (start < s.length())
    {
        int pos = s.findFirst(delim, start);
        if (pos < 0)
        {
            parts.insertLast(s.substr(start));
            break;
        }
        parts.insertLast(s.substr(start, pos - start));
        start = uint(pos) + delim.length();
    }
    return parts;
}

string bytes_to_hex(const array<uint8> &in data)
{
    string raw;
    raw.resize(data.length());
    for (uint i = 0; i < data.length(); i++)
        raw[i] = uint8(data[i]);
    return util_hex_encode(raw);
}

// ─── JSON Serializer (handles nested arrays/dicts) ───────────────────

string mcp_json_escape(const string &in s)
{
    string r = "";
    for (uint i = 0; i < s.length(); i++)
    {
        uint8 c = s[i];
        if (c == 34) r += "\\\"";       // "
        else if (c == 92) r += "\\\\";   // backslash
        else if (c == 10) r += "\\n";    // newline
        else if (c == 13) r += "\\r";    // carriage return
        else if (c == 9) r += "\\t";     // tab
        else
        {
            string ch;
            ch.resize(1);
            ch[0] = c;
            r += ch;
        }
    }
    return r;
}

string mcp_serialize_str_arr(array<string> &in arr)
{
    string r = "[";
    for (uint i = 0; i < arr.length(); i++)
    {
        if (i > 0) r += ",";
        r += "\"" + mcp_json_escape(arr[i]) + "\"";
    }
    return r + "]";
}

string array_mcp_serialize_dict(array<dictionary@> &in arr)
{
    string r = "[";
    for (uint i = 0; i < arr.length(); i++)
    {
        if (i > 0) r += ",";
        if (arr[i] is null) r += "null";
        else r += mcp_serialize_dict(arr[i]);
    }
    return r + "]";
}

string mcp_serialize_dict_arr(array<dictionary@> &in arr)
{
    string r = "[";
    for (uint i = 0; i < arr.length(); i++)
    {
        if (i > 0) r += ",";
        if (arr[i] is null) r += "null";
        else r += mcp_serialize_dict(arr[i]);
    }
    return r + "]";
}

string mcp_serialize_dict(dictionary &in d)
{
    string r = "{";
    array<string> keys = d.getKeys();
    bool first = true;
    for (uint i = 0; i < keys.length(); i++)
    {
        string k = keys[i];
        string val_str = "";
        bool found = false;

        // 1. Try handle types first (array<dictionary@>, dictionary@)
        {
            array<dictionary@>@ ad;
            if (d.get(k, @ad) && ad !is null)
            {
                val_str = mcp_serialize_dict_arr(ad);
                found = true;
            }
        }
        if (!found)
        {
            dictionary@ nd;
            if (d.get(k, @nd) && nd !is null)
            {
                val_str = mcp_serialize_dict(nd);
                found = true;
            }
        }

        // 2. String (before double — double.get can match strings in some engines)
        if (!found)
        {
            string sv;
            if (d.get(k, sv))
            {
                val_str = "\"" + mcp_json_escape(sv) + "\"";
                found = true;
            }
        }

        // 3. Double/number
        if (!found)
        {
            double dv;
            if (d.get(k, dv))
            {
                if (dv == double(int64(dv)) && dv < 1e15 && dv > -1e15)
                    val_str = formatInt(int64(dv));
                else
                    val_str = formatFloat(dv, '', 0, 6);
                found = true;
            }
        }

        // 4. array<string> — must come BEFORE bool: non-null object handles coerce to bool=true
        //    in AngelScript's dictionary, so checking bool first would eat every array<string>.
        if (!found)
        {
            array<string> sa;
            if (d.get(k, sa))
            {
                val_str = mcp_serialize_str_arr(sa);
                found = true;
            }
        }

        // 5. Bool
        if (!found)
        {
            bool bv;
            if (d.get(k, bv))
            {
                val_str = bv ? "true" : "false";
                found = true;
            }
        }

        if (!found)
            val_str = "null";

        if (!first) r += ",";
        r += "\"" + mcp_json_escape(k) + "\":" + val_str;
        first = false;
    }
    return r + "}";
}

void send_response(dictionary &in res)
{
    if (!g_ws.is_open()) return;
    string json = mcp_serialize_dict(res);
    g_ws.send_text(json);
}

double get_dict_double(dictionary &in d, const string &in key, double def = 0)
{
    double v;
    if (d.get(key, v)) return v;
    return def;
}

string get_dict_string(dictionary &in d, const string &in key, const string &in def = "")
{
    string v;
    if (d.get(key, v)) return v;
    return def;
}

bool get_dict_bool(dictionary &in d, const string &in key, bool def = false)
{
    bool v;
    if (d.get(key, v)) return v;
    return def;
}

// ─── Command Handlers ───────────────────────────────────────────────

void cmd_attach(dictionary &in req, dictionary &inout res)
{
    string name = get_dict_string(req, "name");
    double pid_d = get_dict_double(req, "pid");

    if (g_attached && g_proc.alive())
        g_proc.deref();

    if (name != "")
        g_proc = ref_process(name);
    else if (pid_d > 0)
        g_proc = ref_process(uint(pid_d));
    else
    {
        res.set("error", "provide 'name' or 'pid'");
        return;
    }

    if (!g_proc.alive())
    {
        g_attached = false;
        res.set("error", "attach failed");
        return;
    }

    g_attached = true;
    res.set("result", "attached");
    res.set("pid", double(g_proc.pid()));
    res.set("base", to_hex(g_proc.base_address()));
    res.set("peb", to_hex(g_proc.peb()));
}

void cmd_detach(dictionary &inout res)
{
    if (g_proc.alive())
        g_proc.deref();
    g_proc = proc_t();
    g_attached = false;
    res.set("result", "detached");
}

void cmd_process_info(dictionary &inout res)
{
    if (!g_attached || !g_proc.alive())
    {
        res.set("error", "not attached");
        return;
    }
    res.set("pid", double(g_proc.pid()));
    res.set("base", to_hex(g_proc.base_address()));
    res.set("peb", to_hex(g_proc.peb()));
    res.set("alive", g_proc.alive());
}

void cmd_is_valid_address(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    res.set("valid", g_proc.is_valid_address(addr));
    res.set("address", to_hex(addr));
}

void cmd_read_memory(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint size = uint(get_dict_double(req, "size"));
    if (size == 0 || size > 1048576) { res.set("error", "invalid size (max 1MB)"); return; }

    array<uint8> data;
    g_proc.rvm(addr, size, data);
    if (data.length() != size) { res.set("error", "read failed"); return; }

    res.set("data", bytes_to_hex(data));
    res.set("address", to_hex(addr));
    res.set("size", double(size));
}

void cmd_read_values(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    string type = get_dict_string(req, "type");
    uint count = uint(get_dict_double(req, "count", 1));
    if (count == 0) count = 1;
    if (count > 1024) count = 1024;

    array<dictionary@> values;
    for (uint i = 0; i < count; i++)
    {
        dictionary v;
        uint64 a = addr;
        if (type == "u8")       { a += i;     v.set("value", double(g_proc.ru8(a))); v.set("hex", to_hex(g_proc.ru8(a))); }
        else if (type == "u16") { a += i * 2; v.set("value", double(g_proc.ru16(a))); v.set("hex", to_hex(g_proc.ru16(a))); }
        else if (type == "u32") { a += i * 4; v.set("value", double(g_proc.ru32(a))); v.set("hex", to_hex(g_proc.ru32(a))); }
        else if (type == "u64") { a += i * 8; v.set("value", to_hex(g_proc.ru64(a))); }
        else if (type == "i8")  { a += i;     v.set("value", double(g_proc.r8(a))); }
        else if (type == "i16") { a += i * 2; v.set("value", double(g_proc.r16(a))); }
        else if (type == "i32") { a += i * 4; v.set("value", double(g_proc.r32(a))); }
        else if (type == "i64") { a += i * 8; v.set("value", double(g_proc.r64(a))); }
        else if (type == "f32") { a += i * 4; v.set("value", double(g_proc.rf32(a))); }
        else if (type == "f64") { a += i * 8; v.set("value", g_proc.rf64(a)); }
        else { res.set("error", "unknown type: " + type); return; }

        v.set("address", to_hex(a));
        values.insertLast(@v);
    }
    res.set("values", @values);
}

void cmd_read_string(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    int max_len = int(get_dict_double(req, "max_length", 256));
    res.set("value", g_proc.rs(addr, max_len));
    res.set("address", to_hex(addr));
}

void cmd_read_wstring(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    int max_len = int(get_dict_double(req, "max_length", 256));
    res.set("value", g_proc.rws(addr, max_len));
    res.set("address", to_hex(addr));
}

void cmd_read_pointer_chain(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "base"));
    string final_type = get_dict_string(req, "final_type", "ptr");

    array<string> offsets_arr;
    array<dictionary@>@ offsets_raw;
    // offsets come as array of strings
    if (!req.get("offsets", @offsets_raw))
    {
        res.set("error", "missing offsets array");
        return;
    }

    array<dictionary@> chain_steps;

    // Follow the pointer chain
    for (uint i = 0; i < offsets_raw.length(); i++)
    {
        // Each element is a string in the array
        string off_str;
        // The MCP sends offsets as array of strings, but JSON arrays become array<dictionary@>
        // Try to extract string value
        // Actually in Perception JSON, arrays of strings come as... let's handle both
        uint64 prev_addr = addr;
        string offset_hex;

        // Read offset from the dictionary (JSON array element)
        if (offsets_raw[i] !is null)
        {
            // Try to get as string directly - won't work for plain string arrays
            // In Perception JSON, string arrays might be different
        }

        // Fallback: parse from request directly
        // The offsets are sent as an array of strings in JSON
        // Let's try a different approach - get the offsets as a single comma-separated string
    }

    // Alternative: use offsets_csv field
    string offsets_csv = get_dict_string(req, "offsets_csv", "");
    array<string> off_parts;

    // Parse the offsets - they should be available somehow
    // Let's use the raw array approach
    if (offsets_csv == "" && offsets_raw !is null)
    {
        // Read pointer through each offset
        for (uint i = 0; i < offsets_raw.length(); i++)
        {
            string os;
            if (offsets_raw[i] !is null && offsets_raw[i].get("value", os))
            {
                uint64 offset = parse_hex(os);
                uint64 ptr = g_proc.ru64(addr);
                if (ptr == 0) { res.set("error", "null pointer at step " + i + " addr=" + to_hex(addr)); return; }

                dictionary step;
                step.set("step", double(i));
                step.set("read_from", to_hex(addr));
                step.set("pointer_value", to_hex(ptr));
                step.set("offset", to_hex(offset));
                addr = ptr + offset;
                step.set("result", to_hex(addr));
                chain_steps.insertLast(@step);
            }
        }
    }

    // Actually, let me just handle offsets as a comma-separated string sent from MCP
    // The MCP side will convert the array to CSV
    if (offsets_csv != "")
    {
        array<string> parts = str_split(offsets_csv, ",");
        for (uint i = 0; i < parts.length(); i++)
        {
            uint64 offset = parse_hex(parts[i]);
            uint64 ptr = g_proc.ru64(addr);
            if (ptr == 0) { res.set("error", "null pointer at step " + i + " addr=" + to_hex(addr)); return; }

            dictionary step;
            step.set("step", double(i));
            step.set("read_from", to_hex(addr));
            step.set("pointer_value", to_hex(ptr));
            step.set("offset", to_hex(offset));
            addr = ptr + offset;
            step.set("result", to_hex(addr));
            chain_steps.insertLast(@step);
        }
    }

    res.set("chain", @chain_steps);
    res.set("final_address", to_hex(addr));

    // Read final value
    if (final_type == "u8")       res.set("final_value", double(g_proc.ru8(addr)));
    else if (final_type == "u16") res.set("final_value", double(g_proc.ru16(addr)));
    else if (final_type == "u32") res.set("final_value", double(g_proc.ru32(addr)));
    else if (final_type == "u64") res.set("final_value", to_hex(g_proc.ru64(addr)));
    else if (final_type == "i32") res.set("final_value", double(g_proc.r32(addr)));
    else if (final_type == "f32") res.set("final_value", double(g_proc.rf32(addr)));
    else if (final_type == "f64") res.set("final_value", g_proc.rf64(addr));
    else /* ptr */                res.set("final_value", to_hex(g_proc.ru64(addr)));
}

void cmd_read_struct(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 base_addr = parse_hex(get_dict_string(req, "address"));

    // Fields come as a JSON string from the MCP server
    string fields_json = get_dict_string(req, "fields_json");
    if (fields_json == "") { res.set("error", "missing fields_json"); return; }

    // Parse the JSON array of field descriptors
    // Format: [{"name":"x","offset":"0x10","type":"f32"},...]
    // We'll parse manually since AngelScript JSON parse gives a dictionary, not array
    // Use a simple approach: parse each field from the JSON string

    array<dictionary@> result;

    // Simple JSON array parser for our specific format
    int pos = 0;
    while (pos < int(fields_json.length()))
    {
        // Find next '{'
        int obj_start = fields_json.findFirst("{", pos);
        if (obj_start < 0) break;
        int obj_end = fields_json.findFirst("}", obj_start);
        if (obj_end < 0) break;

        string obj_str = fields_json.substr(obj_start, obj_end - obj_start + 1);
        pos = obj_end + 1;

        // Parse the object
        dictionary field_def;
        string err;
        if (!json_parse(obj_str, field_def, err)) continue;

        string name = get_dict_string(field_def, "name", "field");
        string type = get_dict_string(field_def, "type", "u64");
        uint64 offset = parse_hex(get_dict_string(field_def, "offset", "0"));
        int max_chars = int(get_dict_double(field_def, "max_chars", 256));
        uint64 addr = base_addr + offset;

        dictionary f;
        f.set("name", name);
        f.set("offset", to_hex(offset));
        f.set("address", to_hex(addr));

        if (type == "u8")        f.set("value", double(g_proc.ru8(addr)));
        else if (type == "u16")  f.set("value", double(g_proc.ru16(addr)));
        else if (type == "u32")  f.set("value", double(g_proc.ru32(addr)));
        else if (type == "u64")  f.set("value", to_hex(g_proc.ru64(addr)));
        else if (type == "i8")   f.set("value", double(g_proc.r8(addr)));
        else if (type == "i16")  f.set("value", double(g_proc.r16(addr)));
        else if (type == "i32")  f.set("value", double(g_proc.r32(addr)));
        else if (type == "i64")  f.set("value", double(g_proc.r64(addr)));
        else if (type == "f32")  f.set("value", double(g_proc.rf32(addr)));
        else if (type == "f64")  f.set("value", g_proc.rf64(addr));
        else if (type == "string")  f.set("value", g_proc.rs(addr, max_chars));
        else if (type == "wstring") f.set("value", g_proc.rws(addr, max_chars));
        else if (type == "ptr")  f.set("value", to_hex(g_proc.ru64(addr)));
        else f.set("value", "unknown type: " + type);

        result.insertLast(@f);
    }
    res.set("fields", @result);
}

void cmd_read_pointer_array(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint count = uint(get_dict_double(req, "count"));
    int delta = int(get_dict_double(req, "offset_delta"));

    array<uint64>@ ptrs = g_proc.read_pointer_array(addr, count, delta);
    if (ptrs is null) { res.set("error", "read_pointer_array failed"); return; }

    array<string> hex_ptrs;
    for (uint i = 0; i < ptrs.length(); i++)
        hex_ptrs.insertLast(to_hex(ptrs[i]));
    res.set("pointers", hex_ptrs);
    res.set("count", double(ptrs.length()));
}

// ─── Write Commands ──────────────────────────────────────────────────

void cmd_write_memory(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    string hex = get_dict_string(req, "data");

    string raw, err;
    if (!util_hex_decode(hex, raw, err)) { res.set("error", "invalid hex: " + err); return; }

    array<uint8> bytes;
    bytes.resize(raw.length());
    for (uint i = 0; i < raw.length(); i++)
        bytes[i] = uint8(raw[i]);

    if (g_proc.wvm(addr, bytes))
        res.set("result", "wrote " + bytes.length() + " bytes");
    else
        res.set("error", "write failed");
}

void cmd_write_values(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    string type = get_dict_string(req, "type");
    string values_csv = get_dict_string(req, "values_csv");
    if (values_csv == "") { res.set("error", "missing values_csv"); return; }

    array<string> parts = str_split(values_csv, ",");
    uint written = 0;
    for (uint i = 0; i < parts.length(); i++)
    {
        double v = parseFloat(parts[i]);
        bool ok = false;
        uint64 a = addr;
        if (type == "u8")       { a += i;     ok = g_proc.wu8(a, uint8(v)); }
        else if (type == "u16") { a += i * 2; ok = g_proc.wu16(a, uint16(v)); }
        else if (type == "u32") { a += i * 4; ok = g_proc.wu32(a, uint32(v)); }
        else if (type == "u64") { a += i * 8; ok = g_proc.wu64(a, uint64(v)); }
        else if (type == "i8")  { a += i;     ok = g_proc.w8(a, int8(v)); }
        else if (type == "i16") { a += i * 2; ok = g_proc.w16(a, int16(v)); }
        else if (type == "i32") { a += i * 4; ok = g_proc.w32(a, int32(v)); }
        else if (type == "i64") { a += i * 8; ok = g_proc.w64(a, int64(v)); }
        else if (type == "f32") { a += i * 4; ok = g_proc.wf32(a, float(v)); }
        else if (type == "f64") { a += i * 8; ok = g_proc.wf64(a, v); }
        if (ok) written++;
    }
    res.set("result", "wrote " + written + " values");
}

void cmd_write_string(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    string text = get_dict_string(req, "text");
    if (g_proc.ws(addr, text))
        res.set("result", "wrote string (" + text.length() + " chars)");
    else
        res.set("error", "write failed");
}

void cmd_write_wstring(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    string text = get_dict_string(req, "text");
    if (g_proc.wws(addr, text))
        res.set("result", "wrote wstring (" + text.length() + " chars)");
    else
        res.set("error", "write failed");
}

// ─── Pattern Scanning ────────────────────────────────────────────────

void get_scan_region(dictionary &in req, uint64 &out start, uint64 &out size)
{
    string mod_name = get_dict_string(req, "module_name");
    string start_str = get_dict_string(req, "start");
    string size_str = get_dict_string(req, "size");

    if (start_str != "" && size_str != "")
    {
        start = parse_hex(start_str);
        size = parse_hex(size_str);
    }
    else if (mod_name != "")
    {
        uint64 mod_base, mod_size;
        if (g_proc.get_module(mod_name, mod_base, mod_size))
        {
            start = mod_base;
            size = mod_size;
        }
        else
        {
            start = 0;
            size = 0;
        }
    }
    else
    {
        start = g_proc.base_address();
        uint64 dummy;
        uint64 mod_size;
        // Try to get main module size
        // Use base address with a reasonable default
        start = g_proc.base_address();
        size = 0x10000000; // 256MB default scan range
    }
}

void cmd_pattern_scan(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    string sig = get_dict_string(req, "signature");
    if (sig == "") { res.set("error", "missing signature"); return; }

    uint64 start, size;
    get_scan_region(req, start, size);
    if (size == 0) { res.set("error", "could not determine scan region"); return; }

    uint64 result = g_proc.find_code_pattern(start, size, sig);
    if (result == 0)
        res.set("result", "not found");
    else
    {
        res.set("address", to_hex(result));
        res.set("offset_from_base", to_hex(result - start));
    }
}

void cmd_pattern_scan_all(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    string sig = get_dict_string(req, "signature");
    if (sig == "") { res.set("error", "missing signature"); return; }

    uint64 start, size;
    get_scan_region(req, start, size);
    if (size == 0) { res.set("error", "could not determine scan region"); return; }

    uint max_results = uint(get_dict_double(req, "max_results", 500));
    if (max_results == 0 || max_results > 5000) max_results = 500;

    array<uint64> results;
    g_proc.find_all_code_patterns(start, size, sig, results);

    array<string> hex_results;
    uint limit = results.length() < max_results ? results.length() : max_results;
    for (uint i = 0; i < limit; i++)
        hex_results.insertLast(to_hex(results[i]));

    res.set("matches", hex_results);
    res.set("count", double(results.length()));
    if (results.length() > max_results)
        res.set("truncated", true);
}

// ─── Module Info ─────────────────────────────────────────────────────

void cmd_get_module(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    string name = get_dict_string(req, "name");
    uint64 mod_base, mod_size;
    if (g_proc.get_module(name, mod_base, mod_size))
    {
        res.set("base", to_hex(mod_base));
        res.set("size", to_hex(mod_size));
        res.set("end", to_hex(mod_base + mod_size));
    }
    else
        res.set("error", "module not found: " + name);
}

void cmd_get_export(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 mod_base = parse_hex(get_dict_string(req, "module_base"));
    string export_name = get_dict_string(req, "export_name");
    uint64 addr = g_proc.get_proc_address(mod_base, export_name);
    if (addr != 0)
        res.set("address", to_hex(addr));
    else
        res.set("error", "export not found: " + export_name);
}

void cmd_get_import(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 mod_base = parse_hex(get_dict_string(req, "module_base"));
    string import_name = get_dict_string(req, "import_name");
    uint64 addr = g_proc.get_import_rdata_address(mod_base, import_name);
    if (addr != 0)
        res.set("address", to_hex(addr));
    else
        res.set("error", "import not found: " + import_name);
}

// ─── Disassembly ─────────────────────────────────────────────────────

void cmd_disassemble(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint count = uint(get_dict_double(req, "count", 10));
    uint size = uint(get_dict_double(req, "size", 256));
    if (size > 4096) size = 4096;

    array<uint8> code;
    g_proc.rvm(addr, size, code);
    if (code.length() == 0) { res.set("error", "read failed"); return; }

    array<dictionary@> insts;
    zydis_disasm(code, addr, insts);

    uint limit = count < insts.length() ? count : insts.length();
    array<dictionary@> output;
    for (uint i = 0; i < limit; i++)
    {
        if (insts[i] is null) continue;
        dictionary inst;
        int64 runtime_addr;
        string mnemonic, text;
        int64 length;
        insts[i].get("runtime_address", runtime_addr);
        insts[i].get("mnemonic", mnemonic);
        insts[i].get("text", text);
        insts[i].get("length", length);

        inst.set("address", to_hex(uint64(runtime_addr)));
        inst.set("mnemonic", mnemonic);
        inst.set("text", text);
        inst.set("size", double(length));

        // Get bytes for this instruction
        uint64 offset = uint64(runtime_addr) - addr;
        array<uint8> inst_bytes;
        for (uint b = 0; b < uint(length) && (offset + b) < code.length(); b++)
            inst_bytes.insertLast(code[offset + b]);
        inst.set("bytes", bytes_to_hex(inst_bytes));

        output.insertLast(@inst);
    }
    res.set("instructions", @output);
    res.set("count", double(output.length()));
}

// ─── Virtual Memory ──────────────────────────────────────────────────

void cmd_virtual_query(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint64 region_start, region_size;
    uint protection;
    bool heap_likely;

    if (g_proc.virtual_query(addr, region_start, region_size, protection, heap_likely))
    {
        res.set("region_start", to_hex(region_start));
        res.set("region_size", to_hex(region_size));
        res.set("region_end", to_hex(region_start + region_size));
        res.set("protection", double(protection));
        res.set("heap_likely", heap_likely);
    }
    else
        res.set("error", "virtual_query failed");
}

void cmd_get_vad_snapshot(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    bool   heap_only  = get_dict_bool(req, "heap_only");
    bool   compact    = get_dict_bool(req, "compact");          // return just {start,size} — no metadata
    uint64 min_size   = uint64(get_dict_double(req, "min_size", 0));
    uint64 addr_start = parse_hex(get_dict_string(req, "addr_start", "0x0"));
    uint64 addr_end   = parse_hex(get_dict_string(req, "addr_end",   "0x0")); // 0 = no upper limit
    bool   filter_addr = (addr_end != 0);

    array<dictionary@>@ vads = g_proc.get_vad_snapshot(heap_only);
    if (vads is null) { res.set("error", "VAD snapshot failed"); return; }

    array<dictionary@> output;
    for (uint i = 0; i < vads.length(); i++)
    {
        if (vads[i] is null) continue;
        int64 start, sz, end_v, prot, heap;
        vads[i].get("start", start);
        vads[i].get("size", sz);
        vads[i].get("end", end_v);
        vads[i].get("protection", prot);
        vads[i].get("heap_likely", heap);

        uint64 u_start = uint64(start);
        uint64 u_size  = uint64(sz);

        if (min_size > 0 && u_size < min_size) continue;
        if (filter_addr && (u_start + u_size <= addr_start || u_start >= addr_end)) continue;

        dictionary entry;
        entry.set("start", to_hex(u_start));
        entry.set("size",  to_hex(u_size));
        if (!compact)
        {
            entry.set("end",        to_hex(uint64(end_v)));
            entry.set("protection", double(prot));
            entry.set("heap_likely", heap != 0);
        }
        output.insertLast(@entry);
    }
    res.set("regions", @output);
    res.set("count", double(output.length()));
}

void cmd_alloc_vm(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint size = uint(get_dict_double(req, "size"));
    uint64 addr = g_proc.alloc_vm(size);
    if (addr != 0)
        res.set("address", to_hex(addr));
    else
        res.set("error", "allocation failed");
}

void cmd_free_vm(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    if (g_proc.free_vm(addr))
        res.set("result", "freed");
    else
        res.set("error", "free failed");
}

// ─── TEBs ────────────────────────────────────────────────────────────

void cmd_get_tebs(dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    array<uint64>@ tebs = g_proc.get_all_tebs();
    if (tebs is null) { res.set("error", "get_all_tebs failed"); return; }
    array<string> hex_tebs;
    for (uint i = 0; i < tebs.length(); i++)
        hex_tebs.insertLast(to_hex(tebs[i]));
    res.set("tebs", hex_tebs);
    res.set("count", double(tebs.length()));
}

// ─── Value Scanning ──────────────────────────────────────────────────

void cmd_scan_value(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    string type = get_dict_string(req, "type");
    bool heap_only = get_dict_bool(req, "heap_only");

    array<uint64>@ results;
    if (type == "u32")
    {
        double v; req.get("value", v);
        @results = g_proc.scan_u32(uint(v), heap_only);
    }
    else if (type == "u64")
    {
        string v = get_dict_string(req, "value");
        @results = g_proc.scan_u64(parse_hex(v), heap_only);
    }
    else if (type == "float")
    {
        double v; req.get("value", v);
        @results = g_proc.scan_float(float(v), heap_only);
    }
    else if (type == "double")
    {
        double v; req.get("value", v);
        @results = g_proc.scan_double(v, heap_only);
    }
    else if (type == "string")
    {
        string v = get_dict_string(req, "value");
        @results = g_proc.scan_string(v, heap_only);
    }
    else if (type == "wstring")
    {
        string v = get_dict_string(req, "value");
        @results = g_proc.scan_wstring(v, heap_only);
    }
    else if (type == "pointer")
    {
        string v = get_dict_string(req, "value");
        @results = g_proc.scan_pointer(parse_hex(v), heap_only);
    }
    else
    {
        res.set("error", "unknown scan type: " + type);
        return;
    }

    if (results is null) { res.set("error", "scan returned null"); return; }

    uint page_offset = uint(get_dict_double(req, "page_offset", 0));
    uint page_limit  = uint(get_dict_double(req, "page_limit",  1000));
    if (page_limit == 0 || page_limit > 5000) page_limit = 1000;

    array<string> hex_results;
    uint from = page_offset < results.length() ? page_offset : results.length();
    uint to   = from + page_limit;
    if (to > results.length()) to = results.length();
    for (uint i = from; i < to; i++)
        hex_results.insertLast(to_hex(results[i]));

    res.set("addresses", hex_results);
    res.set("count",      double(results.length()));
    res.set("page_offset", double(from));
    res.set("page_limit",  double(page_limit));
    if (to < results.length())
        res.set("has_more", true);
}

// ─── Advanced RE: Cross-references ───────────────────────────────────

void cmd_find_xrefs(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 target = parse_hex(get_dict_string(req, "target"));

    uint64 start, size;
    get_scan_region(req, start, size);
    if (size == 0) { res.set("error", "could not determine scan region"); return; }

    // Search for relative 32-bit offsets (RIP-relative addressing)
    // and absolute 64-bit pointers
    array<string> rel_xrefs;
    array<string> abs_xrefs;

    // Scan for absolute pointer references
    array<uint64>@ ptr_refs = g_proc.scan_pointer(target, false);
    if (ptr_refs !is null)
    {
        for (uint i = 0; i < ptr_refs.length() && i < 500; i++)
        {
            if (ptr_refs[i] >= start && ptr_refs[i] < start + size)
                abs_xrefs.insertLast(to_hex(ptr_refs[i]));
        }
    }

    // Scan for RIP-relative references (rel32 patterns)
    // For each 4KB chunk in the region, look for rel32 that points to target
    uint64 chunk_size = 4096;
    for (uint64 off = 0; off < size && rel_xrefs.length() < 500; off += chunk_size)
    {
        uint read_sz = uint(chunk_size < (size - off) ? chunk_size : (size - off));
        array<uint8> chunk;
        g_proc.rvm(start + off, read_sz, chunk);
        if (chunk.length() < 5) continue;

        for (uint i = 0; i < chunk.length() - 4; i++)
        {
            // Read 32-bit relative offset
            int32 rel = int32(chunk[i]) | (int32(chunk[i+1]) << 8) | (int32(chunk[i+2]) << 16) | (int32(chunk[i+3]) << 24);
            uint64 ref_addr = start + off + i + 4; // address after the rel32
            uint64 resolved = uint64(int64(ref_addr) + int64(rel));
            if (resolved == target)
            {
                // Found a relative reference, back up to find the instruction
                rel_xrefs.insertLast(to_hex(start + off + i - 1)); // likely instruction start is 1 byte before
            }
        }
    }

    res.set("absolute_refs", abs_xrefs);
    res.set("relative_refs", rel_xrefs);
    res.set("total", double(abs_xrefs.length() + rel_xrefs.length()));
}

// ─── Advanced RE: VTable Analysis ────────────────────────────────────

void cmd_analyze_vtable(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 vtable_addr = parse_hex(get_dict_string(req, "address"));
    uint max_entries = uint(get_dict_double(req, "max_entries", 50));
    bool disasm_preview = get_dict_bool(req, "disasm_preview");

    array<dictionary@> entries;
    for (uint i = 0; i < max_entries; i++)
    {
        uint64 func_ptr = g_proc.ru64(vtable_addr + i * 8);
        if (func_ptr == 0) break;
        if (!g_proc.is_valid_address(func_ptr)) break;

        dictionary entry;
        entry.set("index", double(i));
        entry.set("address", to_hex(vtable_addr + i * 8));
        entry.set("function", to_hex(func_ptr));

        if (disasm_preview)
        {
            array<uint8> code;
            g_proc.rvm(func_ptr, 64, code);
            if (code.length() > 0)
            {
                array<dictionary@> insts;
                zydis_disasm(code, func_ptr, insts);
                array<string> preview;
                uint limit = insts.length() < 5 ? insts.length() : 5;
                for (uint j = 0; j < limit; j++)
                {
                    if (insts[j] is null) continue;
                    string text;
                    insts[j].get("text", text);
                    int64 rt_addr;
                    insts[j].get("runtime_address", rt_addr);
                    preview.insertLast(to_hex(uint64(rt_addr)) + ": " + text);
                }
                entry.set("preview", preview);
            }
        }
        entries.insertLast(@entry);
    }
    res.set("entries", @entries);
    res.set("count", double(entries.length()));
}

// ─── Advanced RE: RTTI ───────────────────────────────────────────────

void cmd_read_rtti(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 vtable_addr = parse_hex(get_dict_string(req, "vtable_address"));

    // Read vtable pointer from object
    uint64 vtable = g_proc.ru64(vtable_addr);
    if (vtable == 0 || !g_proc.is_valid_address(vtable))
    {
        res.set("error", "invalid vtable pointer");
        return;
    }

    // MSVC RTTI: vtable[-1] = pointer to RTTI Complete Object Locator
    uint64 col_ptr = g_proc.ru64(vtable - 8);
    if (col_ptr == 0 || !g_proc.is_valid_address(col_ptr))
    {
        res.set("error", "no RTTI COL found at vtable[-1]");
        return;
    }

    // COL structure (64-bit):
    // +0x00: signature (1 for 64-bit)
    // +0x04: offset
    // +0x08: cdOffset
    // +0x0C: pTypeDescriptor (RVA from module base)
    // +0x10: pClassHierarchyDescriptor (RVA)
    // +0x14: pSelf (RVA)
    uint32 sig = g_proc.ru32(col_ptr);
    int32 type_desc_rva = g_proc.r32(col_ptr + 0x0C);
    int32 chd_rva = g_proc.r32(col_ptr + 0x10);
    int32 self_rva = g_proc.r32(col_ptr + 0x14);

    // Calculate base from self pointer
    uint64 image_base = col_ptr - uint64(self_rva);

    // Read type descriptor
    uint64 type_desc = image_base + uint64(type_desc_rva);
    // TypeDescriptor:
    // +0x00: pVFTable
    // +0x08: spare
    // +0x10: name (decorated class name)
    string class_name = g_proc.rs(type_desc + 0x10, 256);

    res.set("vtable", to_hex(vtable));
    res.set("col", to_hex(col_ptr));
    res.set("image_base", to_hex(image_base));
    res.set("class_name", class_name);
    res.set("signature", double(sig));

    // Read class hierarchy
    uint64 chd = image_base + uint64(chd_rva);
    uint32 num_bases = g_proc.ru32(chd + 0x08);
    int32 base_array_rva = g_proc.r32(chd + 0x0C);
    uint64 base_array = image_base + uint64(base_array_rva);

    array<string> hierarchy;
    uint limit = num_bases < 32 ? num_bases : 32;
    for (uint i = 0; i < limit; i++)
    {
        int32 bcd_rva = g_proc.r32(base_array + i * 4);
        uint64 bcd = image_base + uint64(bcd_rva);
        int32 base_td_rva = g_proc.r32(bcd);
        uint64 base_td = image_base + uint64(base_td_rva);
        string base_name = g_proc.rs(base_td + 0x10, 256);
        hierarchy.insertLast(base_name);
    }
    res.set("hierarchy", hierarchy);
}

// ─── Advanced RE: Signature Generation ───────────────────────────────

void cmd_generate_signature(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint length = uint(get_dict_double(req, "length", 32));
    if (length > 256) length = 256;

    array<uint8> code;
    g_proc.rvm(addr, length, code);
    if (code.length() == 0) { res.set("error", "read failed"); return; }

    // Disassemble to find relocatable bytes
    array<dictionary@> insts;
    zydis_disasm(code, addr, insts);

    // Build signature by wildcarding displacement/immediate bytes for relative addresses
    array<bool> wildcard;
    wildcard.resize(code.length());
    for (uint i = 0; i < wildcard.length(); i++)
        wildcard[i] = false;

    for (uint i = 0; i < insts.length(); i++)
    {
        if (insts[i] is null) continue;
        int64 inst_addr, inst_len;
        insts[i].get("runtime_address", inst_addr);
        insts[i].get("length", inst_len);

        uint64 offset = uint64(inst_addr) - addr;

        // Check operands for relative/memory references
        array<dictionary@>@ operands;
        if (insts[i].get("operands", @operands) && operands !is null)
        {
            for (uint j = 0; j < operands.length(); j++)
            {
                if (operands[j] is null) continue;
                string op_type;
                operands[j].get("type", op_type);

                bool has_disp;
                if (operands[j].get("mem_has_displacement", has_disp) && has_disp)
                {
                    // Wildcard the last 4 bytes of the instruction (displacement)
                    for (uint b = uint(inst_len) - 4; b < uint(inst_len); b++)
                    {
                        if (offset + b < wildcard.length())
                            wildcard[offset + b] = true;
                    }
                }

                bool is_relative;
                if (operands[j].get("imm_is_relative", is_relative) && is_relative)
                {
                    // Wildcard immediate relative bytes
                    for (uint b = uint(inst_len) - 4; b < uint(inst_len); b++)
                    {
                        if (offset + b < wildcard.length())
                            wildcard[offset + b] = true;
                    }
                }
            }
        }
    }

    // Build IDA-style signature
    string sig = "";
    for (uint i = 0; i < code.length(); i++)
    {
        if (i > 0) sig += " ";
        if (wildcard[i])
            sig += "??";
        else
        {
            uint8 b = code[i];
            uint8 hi = b >> 4;
            uint8 lo = b & 0xF;
            sig += HEX_UPPER.substr(hi, 1);
            sig += HEX_UPPER.substr(lo, 1);
        }
    }

    res.set("signature", sig);
    res.set("address", to_hex(addr));
    res.set("length", double(code.length()));
}

// ─── Advanced RE: Function Bounds ────────────────────────────────────

void cmd_find_function_bounds(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));

    // Scan backwards for common function prologues
    uint64 func_start = 0;
    for (uint64 off = 0; off < 0x10000; off++)
    {
        uint64 check = addr - off;
        array<uint8> bytes;
        g_proc.rvm(check, 4, bytes);
        if (bytes.length() < 4) continue;

        // Common x64 prologues:
        // push rbp = 55, mov rbp,rsp = 48 89 E5
        // sub rsp, XX = 48 83 EC XX or 48 81 EC XX XX XX XX
        // push rbx = 53
        // Also check for CC CC padding before function
        if (off > 0)
        {
            uint8 prev = g_proc.ru8(check - 1);
            if (prev == 0xCC || prev == 0x90) // int3 or nop padding
            {
                // Check if this looks like a prologue
                if (bytes[0] == 0x55 || // push rbp
                    bytes[0] == 0x53 || // push rbx
                    (bytes[0] == 0x48 && bytes[1] == 0x89) || // mov r64, r64
                    (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) || // sub rsp, imm8
                    (bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC) || // sub rsp, imm32
                    (bytes[0] == 0x40 && bytes[1] == 0x53) || // push rbx (REX)
                    (bytes[0] == 0x40 && bytes[1] == 0x55) || // push rbp (REX)
                    (bytes[0] == 0x48 && bytes[1] == 0x8B && bytes[2] == 0xC4)) // mov rax, rsp
                {
                    func_start = check;
                    break;
                }
            }
        }
    }

    if (func_start == 0)
    {
        res.set("error", "could not find function start");
        return;
    }

    // Scan forward for ret instruction
    uint64 func_end = 0;
    array<uint8> scan_buf;
    uint scan_size = 0x10000;
    g_proc.rvm(func_start, scan_size, scan_buf);

    array<dictionary@> insts;
    zydis_disasm(scan_buf, func_start, insts);

    for (uint i = 0; i < insts.length(); i++)
    {
        if (insts[i] is null) continue;
        string mnemonic;
        int64 rt_addr, length;
        insts[i].get("mnemonic", mnemonic);
        insts[i].get("runtime_address", rt_addr);
        insts[i].get("length", length);

        if (uint64(rt_addr) >= addr && (mnemonic == "ret" || mnemonic == "RET"))
        {
            func_end = uint64(rt_addr) + uint64(length);
            break;
        }
    }

    res.set("start", to_hex(func_start));
    if (func_end != 0)
    {
        res.set("end", to_hex(func_end));
        res.set("size", double(func_end - func_start));
    }
}

// ─── Advanced RE: Function Analysis ──────────────────────────────────

void cmd_analyze_function(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint max_size = uint(get_dict_double(req, "max_size", 4096));
    if (max_size > 65536) max_size = 65536;

    array<uint8> code;
    g_proc.rvm(addr, max_size, code);
    if (code.length() == 0) { res.set("error", "read failed"); return; }

    array<dictionary@> insts;
    zydis_disasm(code, addr, insts);

    array<dictionary@> output;
    array<string> call_targets;
    array<string> jump_targets;

    for (uint i = 0; i < insts.length(); i++)
    {
        if (insts[i] is null) continue;
        string mnemonic, text;
        int64 rt_addr, length;
        insts[i].get("mnemonic", mnemonic);
        insts[i].get("text", text);
        insts[i].get("runtime_address", rt_addr);
        insts[i].get("length", length);

        dictionary inst;
        inst.set("address", to_hex(uint64(rt_addr)));
        inst.set("text", text);
        inst.set("mnemonic", mnemonic);

        // Track calls and jumps
        if (mnemonic == "call" || mnemonic == "CALL")
        {
            // Try to resolve target from operands
            array<dictionary@>@ operands;
            if (insts[i].get("operands", @operands) && operands !is null)
            {
                for (uint j = 0; j < operands.length(); j++)
                {
                    if (operands[j] is null) continue;
                    int64 abs_addr;
                    if (operands[j].get("imm_absolute_address", abs_addr))
                        call_targets.insertLast(to_hex(uint64(abs_addr)));
                }
            }
        }
        else if (mnemonic.substr(0, 1) == "j" || mnemonic.substr(0, 1) == "J")
        {
            array<dictionary@>@ operands;
            if (insts[i].get("operands", @operands) && operands !is null)
            {
                for (uint j = 0; j < operands.length(); j++)
                {
                    if (operands[j] is null) continue;
                    int64 abs_addr;
                    if (operands[j].get("imm_absolute_address", abs_addr))
                        jump_targets.insertLast(to_hex(uint64(abs_addr)));
                }
            }
        }

        output.insertLast(@inst);

        // Stop at ret
        if (mnemonic == "ret" || mnemonic == "RET") break;
    }

    res.set("instructions", @output);
    res.set("instruction_count", double(output.length()));
    res.set("call_targets", call_targets);
    res.set("jump_targets", jump_targets);
}

// ─── Memory Dump & Diff ─────────────────────────────────────────────

void cmd_dump_memory_region(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint size = uint(get_dict_double(req, "size"));
    string label = get_dict_string(req, "label");
    if (size > 1048576) { res.set("error", "max 1MB"); return; }

    array<uint8> data;
    g_proc.rvm(addr, size, data);
    if (data.length() != size) { res.set("error", "read failed"); return; }

    // Store snapshot
    dictionary snap;
    snap.set("address", to_hex(addr));
    snap.set("size", double(size));
    snap.set("data", bytes_to_hex(data));
    g_snapshots.set(label, @snap);

    res.set("result", "snapshot '" + label + "' saved (" + size + " bytes at " + to_hex(addr) + ")");
}

void cmd_diff_memory(dictionary &in req, dictionary &inout res)
{
    string label_a = get_dict_string(req, "label_a");
    string label_b = get_dict_string(req, "label_b");

    dictionary@ snap_a, snap_b;
    if (!g_snapshots.get(label_a, @snap_a)) { res.set("error", "snapshot '" + label_a + "' not found"); return; }
    if (!g_snapshots.get(label_b, @snap_b)) { res.set("error", "snapshot '" + label_b + "' not found"); return; }

    string hex_a, hex_b;
    snap_a.get("data", hex_a);
    snap_b.get("data", hex_b);

    string raw_a, raw_b, err;
    util_hex_decode(hex_a, raw_a, err);
    util_hex_decode(hex_b, raw_b, err);

    uint min_len = raw_a.length() < raw_b.length() ? raw_a.length() : raw_b.length();

    array<dictionary@> diffs;
    for (uint i = 0; i < min_len; i++)
    {
        if (uint8(raw_a[i]) != uint8(raw_b[i]))
        {
            dictionary d;
            d.set("offset", to_hex(i));
            d.set("a", double(uint8(raw_a[i])));
            d.set("b", double(uint8(raw_b[i])));
            diffs.insertLast(@d);
            if (diffs.length() >= 1000) break;
        }
    }

    res.set("differences", @diffs);
    res.set("diff_count", double(diffs.length()));
    res.set("compared_bytes", double(min_len));
    if (raw_a.length() != raw_b.length())
        res.set("size_mismatch", true);
}

// ─── Pointer Scan ────────────────────────────────────────────────────

void cmd_scan_pointer_to(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 target    = parse_hex(get_dict_string(req, "target"));
    bool   heap_only = get_dict_bool(req, "heap_only");
    uint   page_offset = uint(get_dict_double(req, "page_offset", 0));
    uint   page_limit  = uint(get_dict_double(req, "page_limit",  1000));
    if (page_limit == 0 || page_limit > 5000) page_limit = 1000;

    array<uint64>@ results = g_proc.scan_pointer(target, heap_only);
    if (results is null) { res.set("error", "scan failed"); return; }

    array<string> hex_results;
    uint from = page_offset < results.length() ? page_offset : results.length();
    uint to   = from + page_limit;
    if (to > results.length()) to = results.length();
    for (uint i = from; i < to; i++)
        hex_results.insertLast(to_hex(results[i]));

    res.set("addresses",   hex_results);
    res.set("count",       double(results.length()));
    res.set("page_offset", double(from));
    res.set("page_limit",  double(page_limit));
    if (to < results.length())
        res.set("has_more", true);
}

// ─── String References ──────────────────────────────────────────────

void cmd_find_string_refs(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    string search = get_dict_string(req, "search_text");

    // First find the strings in memory
    array<uint64>@ string_addrs = g_proc.scan_string(search, false);
    array<uint64>@ wstring_addrs = g_proc.scan_wstring(search, false);

    array<dictionary@> refs;

    // For each found string, look for pointers to it
    if (string_addrs !is null)
    {
        for (uint i = 0; i < string_addrs.length() && i < 20; i++)
        {
            array<uint64>@ ptrs = g_proc.scan_pointer(string_addrs[i], false);
            if (ptrs !is null)
            {
                for (uint j = 0; j < ptrs.length() && j < 50; j++)
                {
                    dictionary r;
                    r.set("string_address", to_hex(string_addrs[i]));
                    r.set("ref_address", to_hex(ptrs[j]));
                    r.set("type", "ansi");
                    refs.insertLast(@r);
                }
            }
        }
    }

    if (wstring_addrs !is null)
    {
        for (uint i = 0; i < wstring_addrs.length() && i < 20; i++)
        {
            array<uint64>@ ptrs = g_proc.scan_pointer(wstring_addrs[i], false);
            if (ptrs !is null)
            {
                for (uint j = 0; j < ptrs.length() && j < 50; j++)
                {
                    dictionary r;
                    r.set("string_address", to_hex(wstring_addrs[i]));
                    r.set("ref_address", to_hex(ptrs[j]));
                    r.set("type", "wide");
                    refs.insertLast(@r);
                }
            }
        }
    }

    res.set("references", @refs);
    res.set("count", double(refs.length()));
}

// ─── Unicorn Emulation ──────────────────────────────────────────────

void cmd_emulate_code(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }

    uint64 code_addr = parse_hex(get_dict_string(req, "code_address"));
    uint code_size = uint(get_dict_double(req, "code_size"));
    uint entry_offset = uint(get_dict_double(req, "entry_offset", 0));
    uint max_insts = uint(get_dict_double(req, "max_instructions", 10000));

    // Read code from target
    array<uint8> code;
    g_proc.rvm(code_addr, code_size, code);
    if (code.length() == 0) { res.set("error", "failed to read code"); return; }

    // Create UC instance
    uint64 uc = uc_create();
    if (uc == 0) { res.set("error", "uc_create failed"); return; }

    // Map code
    uint64 map_addr = 0x10000;
    uint64 map_size = ((code_size + 0xFFF) & ~0xFFF);  // page-align
    if (!uc_mem_map(uc, map_addr, map_size, UC_PROT_ALL))
    {
        uc_close(uc);
        res.set("error", "uc_mem_map failed");
        return;
    }
    uc_mem_write(uc, map_addr, code);

    // Setup stack
    uint64 stack_base = 0x100000;
    uint64 stack_size = 0x10000;
    uint64 stop_addr = 0xDEAD0000;
    uc_mem_map(uc, stack_base, stack_size, UC_PROT_ALL);
    uc_mem_map(uc, stop_addr & ~0xFFF, 0x1000, UC_PROT_ALL);
    uc_setup_stack(uc, stack_base, stack_size, stop_addr);

    // Map additional regions if requested
    array<dictionary@>@ map_regions;
    if (req.get("map_regions", @map_regions) && map_regions !is null)
    {
        for (uint i = 0; i < map_regions.length(); i++)
        {
            if (map_regions[i] is null) continue;
            uint64 r_addr = parse_hex(get_dict_string(map_regions[i], "address"));
            uint r_size = uint(get_dict_double(map_regions[i], "size"));
            uint64 aligned_addr = r_addr & ~0xFFF;
            uint64 aligned_size = ((r_size + (r_addr - aligned_addr) + 0xFFF) & ~0xFFF);

            array<uint8> region_data;
            g_proc.rvm(r_addr, r_size, region_data);
            if (region_data.length() > 0)
            {
                uc_mem_map(uc, aligned_addr, aligned_size, UC_PROT_ALL);
                uc_mem_write(uc, r_addr, region_data);
            }
        }
    }

    // Set initial registers
    dictionary@ regs;
    if (req.get("registers", @regs) && regs !is null)
    {
        array<string> reg_names = regs.getKeys();
        for (uint i = 0; i < reg_names.length(); i++)
        {
            string rn = reg_names[i];
            string rv;
            if (!regs.get(rn, rv)) continue;
            uint64 val = parse_hex(rv);

            int reg_id = -1;
            if (rn == "rax" || rn == "RAX") reg_id = UC_X86_REG_RAX;
            else if (rn == "rbx" || rn == "RBX") reg_id = UC_X86_REG_RBX;
            else if (rn == "rcx" || rn == "RCX") reg_id = UC_X86_REG_RCX;
            else if (rn == "rdx" || rn == "RDX") reg_id = UC_X86_REG_RDX;
            else if (rn == "rsi" || rn == "RSI") reg_id = UC_X86_REG_RSI;
            else if (rn == "rdi" || rn == "RDI") reg_id = UC_X86_REG_RDI;
            else if (rn == "r8"  || rn == "R8")  reg_id = UC_X86_REG_R8;
            else if (rn == "r9"  || rn == "R9")  reg_id = UC_X86_REG_R9;
            else if (rn == "r10" || rn == "R10") reg_id = UC_X86_REG_R10;
            else if (rn == "r11" || rn == "R11") reg_id = UC_X86_REG_R11;
            else if (rn == "r12" || rn == "R12") reg_id = UC_X86_REG_R12;
            else if (rn == "r13" || rn == "R13") reg_id = UC_X86_REG_R13;
            else if (rn == "r14" || rn == "R14") reg_id = UC_X86_REG_R14;
            else if (rn == "r15" || rn == "R15") reg_id = UC_X86_REG_R15;
            else if (rn == "rbp" || rn == "RBP") reg_id = UC_X86_REG_RBP;

            if (reg_id >= 0)
                uc_reg_write64(uc, reg_id, val);
        }
    }

    // Execute
    uint64 start_addr = map_addr + entry_offset;
    int emu_result = uc_start(uc, start_addr, stop_addr, 0, max_insts);

    res.set("emu_result", double(emu_result));

    // Read output registers
    array<string> read_regs;
    array<dictionary@>@ read_regs_raw;
    // Default: read rax
    dictionary reg_out;
    reg_out.set("rax", to_hex(uc_reg_read64(uc, UC_X86_REG_RAX)));
    reg_out.set("rbx", to_hex(uc_reg_read64(uc, UC_X86_REG_RBX)));
    reg_out.set("rcx", to_hex(uc_reg_read64(uc, UC_X86_REG_RCX)));
    reg_out.set("rdx", to_hex(uc_reg_read64(uc, UC_X86_REG_RDX)));
    reg_out.set("rsi", to_hex(uc_reg_read64(uc, UC_X86_REG_RSI)));
    reg_out.set("rdi", to_hex(uc_reg_read64(uc, UC_X86_REG_RDI)));
    reg_out.set("r8",  to_hex(uc_reg_read64(uc, UC_X86_REG_R8)));
    reg_out.set("r9",  to_hex(uc_reg_read64(uc, UC_X86_REG_R9)));
    reg_out.set("rip", to_hex(uc_reg_read64(uc, UC_X86_REG_RIP)));
    res.set("registers", @reg_out);

    if (emu_result != 0)
    {
        res.set("exception", double(uc_get_last_exception(uc)));
        res.set("exception_address", to_hex(uc_get_exception_address(uc)));
    }

    uc_close(uc);
}

// ─── Assemble ────────────────────────────────────────────────────────

void cmd_assemble(dictionary &in req, dictionary &inout res)
{
    // This is a simplified assembler - for complex assembly, use the Zydis encoder API
    // For now, support common instructions
    res.set("error", "use write_memory with pre-assembled hex bytes, or emulate_code for execution");
}

// ─── Hex Dump ────────────────────────────────────────────────────────

void cmd_hex_dump(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint size = uint(get_dict_double(req, "size", 256));
    if (size > 4096) size = 4096;

    array<uint8> data;
    g_proc.rvm(addr, size, data);
    if (data.length() == 0) { res.set("error", "read failed"); return; }

    string dump = "";
    for (uint i = 0; i < data.length(); i += 16)
    {
        // Address
        dump += to_hex(addr + i) + ": ";

        // Hex bytes
        string hex_part = "";
        string ascii_part = "";
        for (uint j = 0; j < 16; j++)
        {
            if (i + j < data.length())
            {
                uint8 b = data[i + j];
                uint8 hi = b >> 4;
                uint8 lo = b & 0xF;
                hex_part += HEX_UPPER.substr(hi, 1);
                hex_part += HEX_UPPER.substr(lo, 1);
                hex_part += " ";

                if (b >= 32 && b < 127)
                {
                    string ch;
                    ch.resize(1);
                    ch[0] = b;
                    ascii_part += ch;
                }
                else
                    ascii_part += ".";
            }
            else
            {
                hex_part += "   ";
                ascii_part += " ";
            }

            if (j == 7) hex_part += " ";
        }

        dump += hex_part + " |" + ascii_part + "|\n";
    }

    res.set("dump", dump);
    res.set("address", to_hex(addr));
    res.set("size", double(data.length()));
}

// ─── CS2 Specific ───────────────────────────────────────────────────

void cmd_cs2_get_interface(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 mod_base = parse_hex(get_dict_string(req, "module_base"));
    string iface_name = get_dict_string(req, "interface_name");
    uint64 addr = g_proc.cs2_get_interface(mod_base, iface_name);
    if (addr != 0)
        res.set("address", to_hex(addr));
    else
        res.set("error", "interface not found");
}

void cmd_cs2_schema_dump(dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    array<dictionary@>@ schema = g_proc.cs2_get_schema_dump();
    if (schema is null) { res.set("error", "schema dump failed"); return; }

    array<dictionary@> output;
    for (uint i = 0; i < schema.length(); i++)
    {
        if (schema[i] is null) continue;
        dictionary entry;
        string name;
        int64 offset;
        schema[i].get("name", name);
        schema[i].get("offset", offset);
        entry.set("name", name);
        entry.set("offset", to_hex(uint64(offset)));
        output.insertLast(@entry);
    }
    res.set("schema", @output);
    res.set("count", double(output.length()));
}

// ─── Scan Heap Regions ───────────────────────────────────────────────
// Scans a caller-supplied list of regions for a value via manual rvm reads.
// Workaround for scan_value/scan_pointer_to not supporting per-region scans.
// regions_csv: "0xSTART:0xSIZE,0xSTART:0xSIZE,..." (build from get_vad_snapshot output)
// type: u32 | u64 | pointer    value: hex string for u64/pointer, number for u32

void cmd_scan_heap_regions(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }

    string regions_csv  = get_dict_string(req, "regions_csv");
    string type         = get_dict_string(req, "type", "u64");
    uint   max_results  = uint(get_dict_double(req, "max_results", 100));
    if (max_results == 0 || max_results > 5000) max_results = 100;

    if (regions_csv == "") { res.set("error", "missing regions_csv"); return; }

    bool   is_u64 = (type == "u64" || type == "pointer");
    bool   is_u32 = (type == "u32");
    if (!is_u64 && !is_u32) { res.set("error", "type must be u32/u64/pointer"); return; }

    uint   val_size = is_u64 ? 8 : 4;
    uint64 u64_val  = 0;
    uint   u32_val  = 0;
    if (is_u64)
    {
        u64_val = parse_hex(get_dict_string(req, "value"));
    }
    else
    {
        double dv; req.get("value", dv);
        u32_val = uint(dv);
    }

    array<string> region_pairs = str_split(regions_csv, ",");
    array<string> found;
    uint total_regions = 0;
    uint64 total_bytes = 0;

    for (uint ri = 0; ri < region_pairs.length() && found.length() < max_results; ri++)
    {
        array<string> parts = str_split(region_pairs[ri], ":");
        if (parts.length() < 2) continue;
        uint64 r_start = parse_hex(parts[0]);
        uint64 r_size  = parse_hex(parts[1]);
        if (r_start == 0 || r_size == 0 || r_size > 64 * 1024 * 1024) continue;

        // Read the region (cap per-region read at 16 MB to avoid stalls)
        uint read_sz = uint(r_size < 16 * 1024 * 1024 ? r_size : 16 * 1024 * 1024);
        array<uint8> data;
        g_proc.rvm(r_start, read_sz, data);
        if (data.length() < val_size) continue;
        total_regions++;
        total_bytes += data.length();

        // Scan aligned at val_size steps — enough for vtable/pointer/u64 scans
        uint scan_end = data.length() - (val_size - 1);
        for (uint i = 0; i < scan_end && found.length() < max_results; i += val_size)
        {
            if (is_u64)
            {
                uint64 v =  uint64(data[i])
                         | (uint64(data[i+1]) << 8)
                         | (uint64(data[i+2]) << 16)
                         | (uint64(data[i+3]) << 24)
                         | (uint64(data[i+4]) << 32)
                         | (uint64(data[i+5]) << 40)
                         | (uint64(data[i+6]) << 48)
                         | (uint64(data[i+7]) << 56);
                if (v == u64_val)
                    found.insertLast(to_hex(r_start + i));
            }
            else
            {
                uint v =  uint(data[i])
                       | (uint(data[i+1]) << 8)
                       | (uint(data[i+2]) << 16)
                       | (uint(data[i+3]) << 24);
                if (v == u32_val)
                    found.insertLast(to_hex(r_start + i));
            }
        }
    }

    res.set("addresses",       found);
    res.set("count",           double(found.length()));
    res.set("regions_scanned", double(total_regions));
    res.set("bytes_scanned",   double(total_bytes));
    if (found.length() >= max_results)
        res.set("truncated", true);
}

// ─── Read And Filter Pointers ────────────────────────────────────────
// Reads `count` pointers at base + i*stride, dereferences each at deref_offset,
// and returns only entries where the dereferenced value equals vtable_check_addr.
// Useful for filtering player arrays by vtable without N round-trip tool calls.

void cmd_read_and_filter_pointers(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }

    uint64 base         = parse_hex(get_dict_string(req, "base"));
    uint   count        = uint(get_dict_double(req, "count", 64));
    uint   stride       = uint(get_dict_double(req, "stride", 8));
    uint64 vtable_check = parse_hex(get_dict_string(req, "vtable_check_addr"));
    uint   deref_offset = uint(get_dict_double(req, "deref_offset", 0));

    if (count == 0 || count > 2048) count = 64;
    if (stride == 0) stride = 8;

    array<dictionary@> matches;

    for (uint i = 0; i < count; i++)
    {
        uint64 ptr_addr = base + uint64(i) * stride;
        uint64 ptr      = g_proc.ru64(ptr_addr);
        if (ptr == 0) continue;

        uint64 check_val = g_proc.ru64(ptr + deref_offset);
        if (check_val != vtable_check) continue;

        dictionary m;
        m.set("index",       double(i));
        m.set("ptr_address", to_hex(ptr_addr));
        m.set("pointer",     to_hex(ptr));
        matches.insertLast(@m);
    }

    res.set("matches", @matches);
    res.set("count",   double(matches.length()));
}

// ─── Request Router ──────────────────────────────────────────────────

void handle_request(dictionary &in req)
{
    string cmd;
    if (!req.get("cmd", cmd)) return;

    string req_id;
    req.get("_id", req_id);

    dictionary res;
    if (req_id != "")
        res.set("_id", req_id);

    if      (cmd == "attach")              cmd_attach(req, res);
    else if (cmd == "detach")              cmd_detach(res);
    else if (cmd == "process_info")        cmd_process_info(res);
    else if (cmd == "is_valid_address")    cmd_is_valid_address(req, res);
    else if (cmd == "read_memory")         cmd_read_memory(req, res);
    else if (cmd == "read_values")         cmd_read_values(req, res);
    else if (cmd == "read_string")         cmd_read_string(req, res);
    else if (cmd == "read_wstring")        cmd_read_wstring(req, res);
    else if (cmd == "read_pointer_chain")  cmd_read_pointer_chain(req, res);
    else if (cmd == "read_struct")         cmd_read_struct(req, res);
    else if (cmd == "read_pointer_array")  cmd_read_pointer_array(req, res);
    else if (cmd == "write_memory")        cmd_write_memory(req, res);
    else if (cmd == "write_values")        cmd_write_values(req, res);
    else if (cmd == "write_string")        cmd_write_string(req, res);
    else if (cmd == "write_wstring")       cmd_write_wstring(req, res);
    else if (cmd == "pattern_scan")        cmd_pattern_scan(req, res);
    else if (cmd == "pattern_scan_all")    cmd_pattern_scan_all(req, res);
    else if (cmd == "get_module")          cmd_get_module(req, res);
    else if (cmd == "get_export")          cmd_get_export(req, res);
    else if (cmd == "get_import")          cmd_get_import(req, res);
    else if (cmd == "disassemble")         cmd_disassemble(req, res);
    else if (cmd == "virtual_query")       cmd_virtual_query(req, res);
    else if (cmd == "get_vad_snapshot")    cmd_get_vad_snapshot(req, res);
    else if (cmd == "alloc_vm")            cmd_alloc_vm(req, res);
    else if (cmd == "free_vm")             cmd_free_vm(req, res);
    else if (cmd == "get_tebs")            cmd_get_tebs(res);
    else if (cmd == "scan_value")          cmd_scan_value(req, res);
    else if (cmd == "find_xrefs")          cmd_find_xrefs(req, res);
    else if (cmd == "analyze_vtable")      cmd_analyze_vtable(req, res);
    else if (cmd == "read_rtti")           cmd_read_rtti(req, res);
    else if (cmd == "generate_signature")  cmd_generate_signature(req, res);
    else if (cmd == "find_function_bounds") cmd_find_function_bounds(req, res);
    else if (cmd == "analyze_function")    cmd_analyze_function(req, res);
    else if (cmd == "dump_memory_region")  cmd_dump_memory_region(req, res);
    else if (cmd == "diff_memory")         cmd_diff_memory(req, res);
    else if (cmd == "scan_pointer_to")     cmd_scan_pointer_to(req, res);
    else if (cmd == "scan_heap_regions")   cmd_scan_heap_regions(req, res);
    else if (cmd == "read_and_filter_pointers") cmd_read_and_filter_pointers(req, res);
    else if (cmd == "find_string_refs")    cmd_find_string_refs(req, res);
    else if (cmd == "emulate_code")        cmd_emulate_code(req, res);
    else if (cmd == "assemble")            cmd_assemble(req, res);
    else if (cmd == "hex_dump")            cmd_hex_dump(req, res);
    else if (cmd == "cs2_get_interface")   cmd_cs2_get_interface(req, res);
    else if (cmd == "cs2_schema_dump")     cmd_cs2_schema_dump(res);
    else
        res.set("error", "unknown command: " + cmd);

    send_response(res);
}

// ─── WebSocket Pump ──────────────────────────────────────────────────

// Ticks since last outbound message — used to throttle keepalive pings
int g_idle_ticks = 0;
const int KEEPALIVE_INTERVAL = 30; // seconds (callback fires at ~1Hz)

void do_disconnect(const string &in reason)
{
    log_console("[RE Server] " + reason + " — reconnecting...");
    g_ws.close();
    g_ws = ws_t();
    g_connected = false;
    g_idle_ticks = 0;
    g_retry_count = 0;
}

void ws_pump()
{
    // Detect silent drops: socket closed without a clean WS close frame
    if (!g_ws.is_open())
    {
        do_disconnect("Connection lost (silent drop)");
        return;
    }

    string msg;
    bool is_text = false;
    bool is_closed = false;

    while (g_ws.poll(msg, is_text, is_closed))
    {
        if (is_text)
        {
            // Swallow hub pings ({"_hub_ping":true}) — no response needed
            if (msg.findFirst("_hub_ping") >= 0) { g_idle_ticks = 0; break; }

            dictionary req;
            string err;
            if (json_parse(msg, req, err))
                handle_request(req);
            else
                log_error("JSON parse error: " + err);
            g_idle_ticks = 0;
        }
        if (is_closed) break;
    }

    if (is_closed)
    {
        do_disconnect("MCP disconnected (clean close)");
        return;
    }

    // Keepalive: send a no-op ping every KEEPALIVE_INTERVAL idle seconds.
    // The hub ignores messages without _id, so this is a free heartbeat.
    g_idle_ticks++;
    if (g_idle_ticks >= KEEPALIVE_INTERVAL)
    {
        g_ws.send_text("{\"_ping\":true}");
        g_idle_ticks = 0;
    }
}

void try_connect()
{
    g_ws = ws_connect("ws://127.0.0.1:9001", 2000);
    if (g_ws.is_open())
    {
        g_connected = true;
        g_idle_ticks = 0;
        g_retry_count = 0;
        log_console("[RE Server] Connected to MCP server. RE tools available.");
    }
    else
    {
        g_ws.close();
        g_ws = ws_t();
        g_retry_count++;
        // Log every 10 retries to avoid spam (callback fires every ~1s)
        if (g_retry_count == 1 || g_retry_count % 10 == 0)
            log_console("[RE Server] Waiting for MCP server... (attempt " + g_retry_count + ")");
    }
}

void ws_callback(int, int)
{
    if (g_connected)
        ws_pump();
    else
        try_connect();
}

// ─── Entry / Exit ────────────────────────────────────────────────────

int main()
{
    log_console("[RE Server] Starting Perception RE server (background mode)...");
    log_console("[RE Server] Will keep looking for MCP at ws://127.0.0.1:9001");

    g_callback_id = register_callback(ws_callback, 1, 0);
    if (g_callback_id == 0)
    {
        log_error("[RE Server] Failed to register callback");
        return -1;
    }

    // Try connecting immediately
    try_connect();

    return 1;
}

void on_unload()
{
    if (g_callback_id != 0)
        unregister_callback(g_callback_id);

    if (g_ws.is_open())
        g_ws.close();
    g_ws = ws_t();

    if (g_proc.alive())
        g_proc.deref();
    g_proc = proc_t();

    g_attached = false;
    log_console("[RE Server] Unloaded");
}
