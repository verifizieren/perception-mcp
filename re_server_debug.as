// ═══════════════════════════════════════════════════════════════════════
// Perception RE Server DEBUG - All operations logged to console
// Drop-in replacement for re_server.as — verbose logging enabled
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

void dbg(const string &in msg)
{
    log_console("[DBG] " + msg);
}

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
        if (c >= 48 && c <= 57)       result |= (c - 48);
        else if (c >= 65 && c <= 70)   result |= (c - 55);
        else if (c >= 97 && c <= 102)  result |= (c - 87);
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

// ─── JSON Serializer ─────────────────────────────────────────────────

string mcp_json_escape(const string &in s)
{
    string r = "";
    for (uint i = 0; i < s.length(); i++)
    {
        uint8 c = s[i];
        if (c == 34) r += "\\\"";
        else if (c == 92) r += "\\\\";
        else if (c == 10) r += "\\n";
        else if (c == 13) r += "\\r";
        else if (c == 9) r += "\\t";
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
        if (!found)
        {
            string sv;
            if (d.get(k, sv))
            {
                val_str = "\"" + mcp_json_escape(sv) + "\"";
                found = true;
            }
        }
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
        if (!found)
        {
            array<string> sa;
            if (d.get(k, sa))
            {
                val_str = mcp_serialize_str_arr(sa);
                found = true;
            }
        }
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
    dbg("SEND: " + json.substr(0, 200) + (json.length() > 200 ? "...[" + json.length() + " chars total]" : ""));
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
    dbg("attach: name='" + name + "' pid=" + pid_d);

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
        dbg("attach: FAILED — process not found");
        g_attached = false;
        res.set("error", "attach failed");
        return;
    }

    g_attached = true;
    res.set("result", "attached");
    res.set("pid", double(g_proc.pid()));
    res.set("base", to_hex(g_proc.base_address()));
    res.set("peb", to_hex(g_proc.peb()));
    dbg("attach: OK pid=" + g_proc.pid() + " base=" + to_hex(g_proc.base_address()));
}

void cmd_detach(dictionary &inout res)
{
    dbg("detach");
    if (g_proc.alive())
        g_proc.deref();
    g_proc = proc_t();
    g_attached = false;
    res.set("result", "detached");
}

void cmd_process_info(dictionary &inout res)
{
    dbg("process_info");
    if (!g_attached || !g_proc.alive())
    {
        res.set("error", "not attached");
        return;
    }
    res.set("pid", double(g_proc.pid()));
    res.set("base", to_hex(g_proc.base_address()));
    res.set("peb", to_hex(g_proc.peb()));
    res.set("alive", g_proc.alive());
    dbg("process_info: pid=" + g_proc.pid());
}

void cmd_is_valid_address(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    bool valid = g_proc.is_valid_address(addr);
    dbg("is_valid_address: " + to_hex(addr) + " -> " + valid);
    res.set("valid", valid);
    res.set("address", to_hex(addr));
}

void cmd_read_memory(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint size = uint(get_dict_double(req, "size"));
    dbg("read_memory: addr=" + to_hex(addr) + " size=" + size);
    if (size == 0 || size > 1048576) { res.set("error", "invalid size (max 1MB)"); return; }

    array<uint8> data;
    g_proc.rvm(addr, size, data);
    if (data.length() != size) { dbg("read_memory: FAILED got " + data.length() + " bytes"); res.set("error", "read failed"); return; }

    res.set("data", bytes_to_hex(data));
    res.set("address", to_hex(addr));
    res.set("size", double(size));
    dbg("read_memory: OK " + data.length() + " bytes");
}

void cmd_read_values(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    string type = get_dict_string(req, "type");
    uint count = uint(get_dict_double(req, "count", 1));
    if (count == 0) count = 1;
    if (count > 1024) count = 1024;
    dbg("read_values: addr=" + to_hex(addr) + " type=" + type + " count=" + count);

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
    dbg("read_values: OK count=" + values.length());
}

void cmd_read_string(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    int max_len = int(get_dict_double(req, "max_length", 256));
    dbg("read_string: addr=" + to_hex(addr) + " max=" + max_len);
    string val = g_proc.rs(addr, max_len);
    res.set("value", val);
    res.set("address", to_hex(addr));
    dbg("read_string: '" + val.substr(0, 64) + "'");
}

void cmd_read_wstring(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    int max_len = int(get_dict_double(req, "max_length", 256));
    dbg("read_wstring: addr=" + to_hex(addr) + " max=" + max_len);
    string val = g_proc.rws(addr, max_len);
    res.set("value", val);
    res.set("address", to_hex(addr));
    dbg("read_wstring: '" + val.substr(0, 64) + "'");
}

void cmd_read_pointer_chain(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "base"));
    string final_type = get_dict_string(req, "final_type", "ptr");
    dbg("read_pointer_chain: base=" + to_hex(addr) + " final_type=" + final_type);

    array<string> offsets_arr;
    array<dictionary@>@ offsets_raw;
    if (!req.get("offsets", @offsets_raw))
    {
        res.set("error", "missing offsets array");
        return;
    }

    array<dictionary@> chain_steps;

    for (uint i = 0; i < offsets_raw.length(); i++)
    {
        uint64 prev_addr = addr;
        string offset_hex;
        if (offsets_raw[i] !is null)
        {
        }
    }

    string offsets_csv = get_dict_string(req, "offsets_csv", "");
    array<string> off_parts;

    if (offsets_csv == "" && offsets_raw !is null)
    {
        for (uint i = 0; i < offsets_raw.length(); i++)
        {
            string os;
            if (offsets_raw[i] !is null && offsets_raw[i].get("value", os))
            {
                uint64 offset = parse_hex(os);
                uint64 ptr = g_proc.ru64(addr);
                dbg("read_pointer_chain: step " + i + " read=" + to_hex(addr) + " ptr=" + to_hex(ptr) + " +offset=" + to_hex(offset));
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

    if (offsets_csv != "")
    {
        array<string> parts = str_split(offsets_csv, ",");
        for (uint i = 0; i < parts.length(); i++)
        {
            uint64 offset = parse_hex(parts[i]);
            uint64 ptr = g_proc.ru64(addr);
            dbg("read_pointer_chain: step " + i + " read=" + to_hex(addr) + " ptr=" + to_hex(ptr) + " +offset=" + to_hex(offset));
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

    if (final_type == "u8")       res.set("final_value", double(g_proc.ru8(addr)));
    else if (final_type == "u16") res.set("final_value", double(g_proc.ru16(addr)));
    else if (final_type == "u32") res.set("final_value", double(g_proc.ru32(addr)));
    else if (final_type == "u64") res.set("final_value", to_hex(g_proc.ru64(addr)));
    else if (final_type == "i32") res.set("final_value", double(g_proc.r32(addr)));
    else if (final_type == "f32") res.set("final_value", double(g_proc.rf32(addr)));
    else if (final_type == "f64") res.set("final_value", g_proc.rf64(addr));
    else                          res.set("final_value", to_hex(g_proc.ru64(addr)));
    dbg("read_pointer_chain: final=" + to_hex(addr));
}

void cmd_read_struct(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 base_addr = parse_hex(get_dict_string(req, "address"));
    string fields_json = get_dict_string(req, "fields_json");
    dbg("read_struct: base=" + to_hex(base_addr) + " fields_json length=" + fields_json.length());
    if (fields_json == "") { res.set("error", "missing fields_json"); return; }

    array<dictionary@> result;
    int pos = 0;
    while (pos < int(fields_json.length()))
    {
        int obj_start = fields_json.findFirst("{", pos);
        if (obj_start < 0) break;
        int obj_end = fields_json.findFirst("}", obj_start);
        if (obj_end < 0) break;
        string obj_str = fields_json.substr(obj_start, obj_end - obj_start + 1);
        pos = obj_end + 1;

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

        dbg("read_struct: field '" + name + "' @+" + to_hex(offset));
        result.insertLast(@f);
    }
    res.set("fields", @result);
    dbg("read_struct: OK " + result.length() + " fields");
}

void cmd_read_pointer_array(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint count = uint(get_dict_double(req, "count"));
    int delta = int(get_dict_double(req, "offset_delta"));
    dbg("read_pointer_array: addr=" + to_hex(addr) + " count=" + count + " delta=" + delta);

    array<uint64>@ ptrs = g_proc.read_pointer_array(addr, count, delta);
    if (ptrs is null) { dbg("read_pointer_array: FAILED"); res.set("error", "read_pointer_array failed"); return; }

    array<string> hex_ptrs;
    for (uint i = 0; i < ptrs.length(); i++)
        hex_ptrs.insertLast(to_hex(ptrs[i]));
    res.set("pointers", hex_ptrs);
    res.set("count", double(ptrs.length()));
    dbg("read_pointer_array: OK " + ptrs.length() + " pointers");
}

// ─── Write Commands ──────────────────────────────────────────────────

void cmd_write_memory(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    string hex = get_dict_string(req, "data");
    dbg("write_memory: addr=" + to_hex(addr) + " hex_len=" + hex.length());

    string raw, err;
    if (!util_hex_decode(hex, raw, err)) { res.set("error", "invalid hex: " + err); return; }

    array<uint8> bytes;
    bytes.resize(raw.length());
    for (uint i = 0; i < raw.length(); i++)
        bytes[i] = uint8(raw[i]);

    if (g_proc.wvm(addr, bytes))
    {
        res.set("result", "wrote " + bytes.length() + " bytes");
        dbg("write_memory: OK " + bytes.length() + " bytes");
    }
    else
    {
        dbg("write_memory: FAILED");
        res.set("error", "write failed");
    }
}

void cmd_write_values(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    string type = get_dict_string(req, "type");
    string values_csv = get_dict_string(req, "values_csv");
    dbg("write_values: addr=" + to_hex(addr) + " type=" + type + " csv='" + values_csv + "'");
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
    dbg("write_values: OK " + written + "/" + parts.length());
}

void cmd_write_string(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    string text = get_dict_string(req, "text");
    dbg("write_string: addr=" + to_hex(addr) + " text='" + text + "'");
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
    dbg("write_wstring: addr=" + to_hex(addr) + " text='" + text + "'");
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
        size = 0x10000000;
    }
    dbg("get_scan_region: start=" + to_hex(start) + " size=" + to_hex(size));
}

void cmd_pattern_scan(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    string sig = get_dict_string(req, "signature");
    dbg("pattern_scan: sig='" + sig + "'");
    if (sig == "") { res.set("error", "missing signature"); return; }

    uint64 start, size;
    get_scan_region(req, start, size);
    if (size == 0) { res.set("error", "could not determine scan region"); return; }

    dbg("pattern_scan: scanning " + to_hex(start) + " size=" + to_hex(size));
    uint64 result = g_proc.find_code_pattern(start, size, sig);
    if (result == 0)
    {
        dbg("pattern_scan: not found");
        res.set("result", "not found");
    }
    else
    {
        dbg("pattern_scan: found at " + to_hex(result));
        res.set("address", to_hex(result));
        res.set("offset_from_base", to_hex(result - start));
    }
}

void cmd_pattern_scan_all(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    string sig = get_dict_string(req, "signature");
    dbg("pattern_scan_all: sig='" + sig + "'");
    if (sig == "") { res.set("error", "missing signature"); return; }

    uint64 start, size;
    get_scan_region(req, start, size);
    if (size == 0) { res.set("error", "could not determine scan region"); return; }

    uint max_results = uint(get_dict_double(req, "max_results", 500));
    if (max_results == 0 || max_results > 5000) max_results = 500;

    dbg("pattern_scan_all: scanning " + to_hex(start) + " size=" + to_hex(size) + " max=" + max_results);
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
    dbg("pattern_scan_all: found " + results.length() + " matches");
}

// ─── Module Info ─────────────────────────────────────────────────────

void cmd_get_module(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    string name = get_dict_string(req, "name");
    dbg("get_module: name='" + name + "'");
    uint64 mod_base, mod_size;
    if (g_proc.get_module(name, mod_base, mod_size))
    {
        res.set("base", to_hex(mod_base));
        res.set("size", to_hex(mod_size));
        res.set("end", to_hex(mod_base + mod_size));
        dbg("get_module: base=" + to_hex(mod_base) + " size=" + to_hex(mod_size));
    }
    else
    {
        dbg("get_module: not found");
        res.set("error", "module not found: " + name);
    }
}

void cmd_get_export(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 mod_base = parse_hex(get_dict_string(req, "module_base"));
    string export_name = get_dict_string(req, "export_name");
    dbg("get_export: mod=" + to_hex(mod_base) + " name='" + export_name + "'");
    uint64 addr = g_proc.get_proc_address(mod_base, export_name);
    if (addr != 0)
    {
        res.set("address", to_hex(addr));
        dbg("get_export: found at " + to_hex(addr));
    }
    else
        res.set("error", "export not found: " + export_name);
}

void cmd_get_import(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 mod_base = parse_hex(get_dict_string(req, "module_base"));
    string import_name = get_dict_string(req, "import_name");
    dbg("get_import: mod=" + to_hex(mod_base) + " name='" + import_name + "'");
    uint64 addr = g_proc.get_import_rdata_address(mod_base, import_name);
    if (addr != 0)
    {
        res.set("address", to_hex(addr));
        dbg("get_import: found at " + to_hex(addr));
    }
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
    dbg("disassemble: addr=" + to_hex(addr) + " count=" + count + " size=" + size);

    array<uint8> code;
    g_proc.rvm(addr, size, code);
    if (code.length() == 0) { dbg("disassemble: read failed"); res.set("error", "read failed"); return; }

    array<dictionary@> insts;
    zydis_disasm(code, addr, insts);
    dbg("disassemble: zydis returned " + insts.length() + " instructions");

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

        uint64 offset = uint64(runtime_addr) - addr;
        array<uint8> inst_bytes;
        for (uint b = 0; b < uint(length) && (offset + b) < code.length(); b++)
            inst_bytes.insertLast(code[offset + b]);
        inst.set("bytes", bytes_to_hex(inst_bytes));

        dbg("  " + to_hex(uint64(runtime_addr)) + ": " + text);
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
    dbg("virtual_query: addr=" + to_hex(addr));
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
        dbg("virtual_query: start=" + to_hex(region_start) + " size=" + to_hex(region_size) + " prot=" + protection + " heap=" + heap_likely);
    }
    else
    {
        dbg("virtual_query: FAILED");
        res.set("error", "virtual_query failed");
    }
}

void cmd_get_vad_snapshot(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    bool   heap_only  = get_dict_bool(req, "heap_only");
    bool   compact    = get_dict_bool(req, "compact");
    uint64 min_size   = uint64(get_dict_double(req, "min_size", 0));
    uint64 addr_start = parse_hex(get_dict_string(req, "addr_start", "0x0"));
    uint64 addr_end   = parse_hex(get_dict_string(req, "addr_end",   "0x0"));
    bool   filter_addr = (addr_end != 0);
    dbg("get_vad_snapshot: heap_only=" + heap_only + " compact=" + compact + " min_size=" + to_hex(min_size));

    array<dictionary@>@ vads = g_proc.get_vad_snapshot(heap_only);
    if (vads is null) { dbg("get_vad_snapshot: FAILED"); res.set("error", "VAD snapshot failed"); return; }
    dbg("get_vad_snapshot: raw " + vads.length() + " entries");

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
    dbg("get_vad_snapshot: output " + output.length() + " regions");
}

void cmd_alloc_vm(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint size = uint(get_dict_double(req, "size"));
    dbg("alloc_vm: size=" + size);
    uint64 addr = g_proc.alloc_vm(size);
    if (addr != 0)
    {
        res.set("address", to_hex(addr));
        dbg("alloc_vm: OK addr=" + to_hex(addr));
    }
    else
    {
        dbg("alloc_vm: FAILED");
        res.set("error", "allocation failed");
    }
}

void cmd_free_vm(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    dbg("free_vm: addr=" + to_hex(addr));
    if (g_proc.free_vm(addr))
    {
        res.set("result", "freed");
        dbg("free_vm: OK");
    }
    else
    {
        dbg("free_vm: FAILED");
        res.set("error", "free failed");
    }
}

// ─── TEBs ────────────────────────────────────────────────────────────

void cmd_get_tebs(dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    dbg("get_tebs");
    array<uint64>@ tebs = g_proc.get_all_tebs();
    if (tebs is null) { dbg("get_tebs: FAILED"); res.set("error", "get_all_tebs failed"); return; }
    array<string> hex_tebs;
    for (uint i = 0; i < tebs.length(); i++)
    {
        hex_tebs.insertLast(to_hex(tebs[i]));
        dbg("  TEB[" + i + "] = " + to_hex(tebs[i]));
    }
    res.set("tebs", hex_tebs);
    res.set("count", double(tebs.length()));
    dbg("get_tebs: OK " + tebs.length() + " threads");
}

// ─── Value Scanning ──────────────────────────────────────────────────

void cmd_scan_value(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    string type = get_dict_string(req, "type");
    bool heap_only = get_dict_bool(req, "heap_only");
    double num_val = get_dict_double(req, "value", 0);
    string str_val = get_dict_string(req, "value", "");
    dbg("scan_value: type=" + type + " heap_only=" + heap_only + " num_val=" + num_val + " str_val='" + str_val + "'");

    array<uint64>@ results;
    if (type == "u32")
    {
        dbg("scan_value: calling scan_u32(" + uint(num_val) + ")");
        @results = g_proc.scan_u32(uint(num_val), heap_only);
    }
    else if (type == "u64")
    {
        dbg("scan_value: calling scan_u64(" + str_val + ")");
        @results = g_proc.scan_u64(parse_hex(str_val), heap_only);
    }
    else if (type == "float")
    {
        dbg("scan_value: calling scan_float(" + num_val + ")");
        @results = g_proc.scan_float(float(num_val), heap_only);
    }
    else if (type == "double")
    {
        dbg("scan_value: calling scan_double(" + num_val + ")");
        @results = g_proc.scan_double(num_val, heap_only);
    }
    else if (type == "string")
    {
        string v = get_dict_string(req, "value");
        dbg("scan_value: calling scan_string('" + v + "')");
        @results = g_proc.scan_string(v, heap_only);
    }
    else if (type == "wstring")
    {
        string v = get_dict_string(req, "value");
        dbg("scan_value: calling scan_wstring('" + v + "')");
        @results = g_proc.scan_wstring(v, heap_only);
    }
    else if (type == "pointer")
    {
        string v = get_dict_string(req, "value");
        dbg("scan_value: calling scan_pointer(" + v + ")");
        @results = g_proc.scan_pointer(parse_hex(v), heap_only);
    }
    else
    {
        res.set("error", "unknown scan type: " + type);
        return;
    }

    if (results is null) { dbg("scan_value: returned null"); res.set("error", "scan returned null"); return; }
    dbg("scan_value: raw results=" + results.length());

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
    dbg("scan_value: returning " + hex_results.length() + " of " + results.length() + " results");
}

// ─── Advanced RE: Cross-references ───────────────────────────────────

void cmd_find_xrefs(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 target = parse_hex(get_dict_string(req, "target"));
    dbg("find_xrefs: target=" + to_hex(target));
    if (target == 0) { res.set("error", "invalid target address"); return; }

    uint64 start, size;
    get_scan_region(req, start, size);
    if (size == 0) { res.set("error", "could not determine scan region"); return; }

    array<string> rel_xrefs;
    array<string> abs_xrefs;

    dbg("find_xrefs: scanning for absolute pointer refs...");
    array<uint64>@ ptr_refs = g_proc.scan_pointer(target, false);
    if (ptr_refs !is null)
    {
        dbg("find_xrefs: scan_pointer returned " + ptr_refs.length() + " hits");
        for (uint i = 0; i < ptr_refs.length() && i < 500; i++)
        {
            if (ptr_refs[i] >= start && ptr_refs[i] < start + size)
                abs_xrefs.insertLast(to_hex(ptr_refs[i]));
        }
    }
    else
        dbg("find_xrefs: scan_pointer returned null");

    dbg("find_xrefs: scanning for relative refs in " + to_hex(start) + "+" + to_hex(size) + "...");
    uint64 chunk_size = 4096;
    uint chunks_done = 0;
    for (uint64 off = 0; off < size && rel_xrefs.length() < 500; off += chunk_size)
    {
        uint read_sz = uint(chunk_size < (size - off) ? chunk_size : (size - off));
        array<uint8> chunk;
        g_proc.rvm(start + off, read_sz, chunk);
        if (chunk.length() < 5) continue;

        for (uint i = 0; i < chunk.length() - 4; i++)
        {
            int32 rel = int32(chunk[i]) | (int32(chunk[i+1]) << 8) | (int32(chunk[i+2]) << 16) | (int32(chunk[i+3]) << 24);
            uint64 ref_addr = start + off + i + 4;
            uint64 resolved = uint64(int64(ref_addr) + int64(rel));
            if (resolved == target)
                rel_xrefs.insertLast(to_hex(start + off + i - 1));
        }
        chunks_done++;
        if (chunks_done % 1000 == 0)
            dbg("find_xrefs: scanned " + chunks_done + " chunks, rel_xrefs=" + rel_xrefs.length());
    }

    res.set("absolute_refs", abs_xrefs);
    res.set("relative_refs", rel_xrefs);
    res.set("total", double(abs_xrefs.length() + rel_xrefs.length()));
    dbg("find_xrefs: done abs=" + abs_xrefs.length() + " rel=" + rel_xrefs.length());
}

// ─── Advanced RE: VTable Analysis ────────────────────────────────────

void cmd_analyze_vtable(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 vtable_addr = parse_hex(get_dict_string(req, "address"));
    uint max_entries = uint(get_dict_double(req, "max_entries", 50));
    bool disasm_preview = get_dict_bool(req, "disasm_preview");
    dbg("analyze_vtable: addr=" + to_hex(vtable_addr) + " max=" + max_entries + " disasm=" + disasm_preview);

    array<dictionary@> entries;
    for (uint i = 0; i < max_entries; i++)
    {
        uint64 func_ptr = g_proc.ru64(vtable_addr + i * 8);
        if (func_ptr == 0) { dbg("analyze_vtable: null at slot " + i); break; }
        if (!g_proc.is_valid_address(func_ptr)) { dbg("analyze_vtable: invalid addr at slot " + i + ": " + to_hex(func_ptr)); break; }

        dbg("analyze_vtable: slot[" + i + "] = " + to_hex(func_ptr));
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
                    dbg("    " + to_hex(uint64(rt_addr)) + ": " + text);
                }
                entry.set("preview", preview);
            }
        }
        entries.insertLast(@entry);
    }
    res.set("entries", @entries);
    res.set("count", double(entries.length()));
    dbg("analyze_vtable: OK " + entries.length() + " entries");
}

// ─── Advanced RE: RTTI ───────────────────────────────────────────────

void cmd_read_rtti(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 vtable_addr = parse_hex(get_dict_string(req, "vtable_address"));
    dbg("read_rtti: vtable_addr=" + to_hex(vtable_addr));

    uint64 vtable = g_proc.ru64(vtable_addr);
    dbg("read_rtti: vtable ptr = " + to_hex(vtable));
    if (vtable == 0 || !g_proc.is_valid_address(vtable))
    {
        dbg("read_rtti: invalid vtable pointer");
        res.set("error", "invalid vtable pointer");
        return;
    }

    uint64 col_ptr = g_proc.ru64(vtable - 8);
    dbg("read_rtti: COL ptr = " + to_hex(col_ptr));
    if (col_ptr == 0 || !g_proc.is_valid_address(col_ptr))
    {
        dbg("read_rtti: no COL found");
        res.set("error", "no RTTI COL found at vtable[-1]");
        return;
    }

    uint32 sig = g_proc.ru32(col_ptr);
    int32 type_desc_rva = g_proc.r32(col_ptr + 0x0C);
    int32 chd_rva = g_proc.r32(col_ptr + 0x10);
    int32 self_rva = g_proc.r32(col_ptr + 0x14);
    dbg("read_rtti: sig=" + sig + " type_desc_rva=" + type_desc_rva + " chd_rva=" + chd_rva + " self_rva=" + self_rva);

    uint64 image_base = col_ptr - uint64(self_rva);
    uint64 type_desc = image_base + uint64(type_desc_rva);
    string class_name = g_proc.rs(type_desc + 0x10, 256);
    dbg("read_rtti: class_name='" + class_name + "' image_base=" + to_hex(image_base));

    res.set("vtable", to_hex(vtable));
    res.set("col", to_hex(col_ptr));
    res.set("image_base", to_hex(image_base));
    res.set("class_name", class_name);
    res.set("signature", double(sig));

    uint64 chd = image_base + uint64(chd_rva);
    uint32 num_bases = g_proc.ru32(chd + 0x08);
    int32 base_array_rva = g_proc.r32(chd + 0x0C);
    uint64 base_array = image_base + uint64(base_array_rva);
    dbg("read_rtti: num_bases=" + num_bases + " base_array=" + to_hex(base_array));

    array<string> hierarchy;
    uint limit = num_bases < 32 ? num_bases : 32;
    for (uint i = 0; i < limit; i++)
    {
        int32 bcd_rva = g_proc.r32(base_array + i * 4);
        uint64 bcd = image_base + uint64(bcd_rva);
        int32 base_td_rva = g_proc.r32(bcd);
        uint64 base_td = image_base + uint64(base_td_rva);
        string base_name = g_proc.rs(base_td + 0x10, 256);
        dbg("read_rtti:   base[" + i + "] = '" + base_name + "'");
        hierarchy.insertLast(base_name);
    }
    res.set("hierarchy", hierarchy);
    dbg("read_rtti: OK");
}

// ─── Advanced RE: Signature Generation ───────────────────────────────

void cmd_generate_signature(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint length = uint(get_dict_double(req, "length", 32));
    if (length > 256) length = 256;
    dbg("generate_signature: addr=" + to_hex(addr) + " length=" + length);

    array<uint8> code;
    g_proc.rvm(addr, length, code);
    if (code.length() == 0) { dbg("generate_signature: read failed"); res.set("error", "read failed"); return; }

    array<dictionary@> insts;
    zydis_disasm(code, addr, insts);
    dbg("generate_signature: disassembled " + insts.length() + " instructions");

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

        array<dictionary@>@ operands;
        if (insts[i].get("operands", @operands) && operands !is null)
        {
            for (uint j = 0; j < operands.length(); j++)
            {
                if (operands[j] is null) continue;
                bool has_disp;
                if (operands[j].get("mem_has_displacement", has_disp) && has_disp)
                {
                    for (uint b = uint(inst_len) - 4; b < uint(inst_len); b++)
                        if (offset + b < wildcard.length())
                            wildcard[offset + b] = true;
                }
                bool is_relative;
                if (operands[j].get("imm_is_relative", is_relative) && is_relative)
                {
                    for (uint b = uint(inst_len) - 4; b < uint(inst_len); b++)
                        if (offset + b < wildcard.length())
                            wildcard[offset + b] = true;
                }
            }
        }
    }

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
    dbg("generate_signature: sig='" + sig.substr(0, 80) + (sig.length() > 80 ? "..." : "") + "'");
}

// ─── Advanced RE: Function Bounds ────────────────────────────────────

void cmd_find_function_bounds(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    dbg("find_function_bounds: addr=" + to_hex(addr));

    uint64 func_start = 0;
    for (uint64 off = 0; off < 0x10000; off++)
    {
        uint64 check = addr - off;
        array<uint8> bytes;
        g_proc.rvm(check, 4, bytes);
        if (bytes.length() < 4) continue;

        if (off > 0)
        {
            uint8 prev = g_proc.ru8(check - 1);
            if (prev == 0xCC || prev == 0x90)
            {
                if (bytes[0] == 0x55 ||
                    bytes[0] == 0x53 ||
                    (bytes[0] == 0x48 && bytes[1] == 0x89) ||
                    (bytes[0] == 0x48 && bytes[1] == 0x83 && bytes[2] == 0xEC) ||
                    (bytes[0] == 0x48 && bytes[1] == 0x81 && bytes[2] == 0xEC) ||
                    (bytes[0] == 0x40 && bytes[1] == 0x53) ||
                    (bytes[0] == 0x40 && bytes[1] == 0x55) ||
                    (bytes[0] == 0x48 && bytes[1] == 0x8B && bytes[2] == 0xC4))
                {
                    func_start = check;
                    break;
                }
            }
        }
    }

    if (func_start == 0)
    {
        dbg("find_function_bounds: could not find start");
        res.set("error", "could not find function start");
        return;
    }
    dbg("find_function_bounds: start=" + to_hex(func_start));

    uint64 func_end = 0;
    array<uint8> scan_buf;
    uint scan_size = 0x10000;
    g_proc.rvm(func_start, scan_size, scan_buf);

    array<dictionary@> insts;
    zydis_disasm(scan_buf, func_start, insts);
    dbg("find_function_bounds: disassembled " + insts.length() + " instructions");

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
        dbg("find_function_bounds: end=" + to_hex(func_end) + " size=" + (func_end - func_start));
    }
    else
        dbg("find_function_bounds: end not found");
}

// ─── Advanced RE: Function Analysis ──────────────────────────────────

void cmd_analyze_function(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint max_size = uint(get_dict_double(req, "max_size", 4096));
    if (max_size > 65536) max_size = 65536;
    dbg("analyze_function: addr=" + to_hex(addr) + " max_size=" + max_size);

    array<uint8> code;
    g_proc.rvm(addr, max_size, code);
    if (code.length() == 0) { dbg("analyze_function: read failed"); res.set("error", "read failed"); return; }

    array<dictionary@> insts;
    zydis_disasm(code, addr, insts);
    dbg("analyze_function: disassembled " + insts.length() + " instructions");

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

        if (mnemonic == "call" || mnemonic == "CALL")
        {
            array<dictionary@>@ operands;
            if (insts[i].get("operands", @operands) && operands !is null)
            {
                for (uint j = 0; j < operands.length(); j++)
                {
                    if (operands[j] is null) continue;
                    int64 abs_addr;
                    if (operands[j].get("imm_absolute_address", abs_addr))
                    {
                        call_targets.insertLast(to_hex(uint64(abs_addr)));
                        dbg("analyze_function:   CALL -> " + to_hex(uint64(abs_addr)));
                    }
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

        dbg("  " + to_hex(uint64(rt_addr)) + ": " + text);
        output.insertLast(@inst);

        if (mnemonic == "ret" || mnemonic == "RET") { dbg("analyze_function: hit RET at " + to_hex(uint64(rt_addr))); break; }
    }

    res.set("instructions", @output);
    res.set("instruction_count", double(output.length()));
    res.set("call_targets", call_targets);
    res.set("jump_targets", jump_targets);
    dbg("analyze_function: OK insts=" + output.length() + " calls=" + call_targets.length() + " jumps=" + jump_targets.length());
}

// ─── Memory Dump & Diff ─────────────────────────────────────────────

void cmd_dump_memory_region(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint size = uint(get_dict_double(req, "size"));
    string label = get_dict_string(req, "label");
    dbg("dump_memory_region: addr=" + to_hex(addr) + " size=" + size + " label='" + label + "'");
    if (size > 1048576) { res.set("error", "max 1MB"); return; }

    array<uint8> data;
    g_proc.rvm(addr, size, data);
    if (data.length() != size) { dbg("dump_memory_region: read failed got " + data.length()); res.set("error", "read failed"); return; }

    dictionary snap;
    snap.set("address", to_hex(addr));
    snap.set("size", double(size));
    snap.set("data", bytes_to_hex(data));
    g_snapshots.set(label, @snap);

    res.set("result", "snapshot '" + label + "' saved (" + size + " bytes at " + to_hex(addr) + ")");
    dbg("dump_memory_region: snapshot '" + label + "' saved");
}

void cmd_diff_memory(dictionary &in req, dictionary &inout res)
{
    string label_a = get_dict_string(req, "label_a");
    string label_b = get_dict_string(req, "label_b");
    dbg("diff_memory: '" + label_a + "' vs '" + label_b + "'");

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
    dbg("diff_memory: comparing " + min_len + " bytes");

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
            dbg("  diff @+" + to_hex(i) + ": " + uint8(raw_a[i]) + " -> " + uint8(raw_b[i]));
            if (diffs.length() >= 1000) break;
        }
    }

    res.set("differences", @diffs);
    res.set("diff_count", double(diffs.length()));
    res.set("compared_bytes", double(min_len));
    if (raw_a.length() != raw_b.length())
        res.set("size_mismatch", true);
    dbg("diff_memory: OK " + diffs.length() + " differences");
}

// ─── Pointer Scan ────────────────────────────────────────────────────

void cmd_scan_pointer_to(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 target    = parse_hex(get_dict_string(req, "target"));
    if (target == 0) { res.set("error", "invalid target address (got 0)"); return; }
    bool   heap_only = get_dict_bool(req, "heap_only");
    uint   page_offset = uint(get_dict_double(req, "page_offset", 0));
    uint   page_limit  = uint(get_dict_double(req, "page_limit",  1000));
    if (page_limit == 0 || page_limit > 5000) page_limit = 1000;
    dbg("scan_pointer_to: target=" + to_hex(target) + " heap_only=" + heap_only + " page_offset=" + page_offset + " page_limit=" + page_limit);

    dbg("scan_pointer_to: calling g_proc.scan_pointer...");
    array<uint64>@ results = g_proc.scan_pointer(target, heap_only);
    if (results is null) { dbg("scan_pointer_to: scan_pointer returned null"); res.set("error", "scan failed"); return; }
    dbg("scan_pointer_to: scan_pointer returned " + results.length() + " results");

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
    dbg("scan_pointer_to: returning " + hex_results.length() + " of " + results.length());
}

// ─── String References ──────────────────────────────────────────────

void cmd_find_string_refs(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    string search = get_dict_string(req, "search_text");
    if (search.length() == 0) { res.set("error", "search_text is empty"); return; }
    dbg("find_string_refs: search='" + search + "'");

    dbg("find_string_refs: calling scan_string...");
    array<uint64>@ string_addrs = g_proc.scan_string(search, false);
    dbg("find_string_refs: scan_string returned " + (string_addrs is null ? "null" : "" + string_addrs.length()) + " hits");

    dbg("find_string_refs: calling scan_wstring...");
    array<uint64>@ wstring_addrs = g_proc.scan_wstring(search, false);
    dbg("find_string_refs: scan_wstring returned " + (wstring_addrs is null ? "null" : "" + wstring_addrs.length()) + " hits");

    array<dictionary@> refs;

    if (string_addrs !is null)
    {
        for (uint i = 0; i < string_addrs.length() && i < 20; i++)
        {
            dbg("find_string_refs: scanning pointers to ANSI match[" + i + "] @ " + to_hex(string_addrs[i]));
            array<uint64>@ ptrs = g_proc.scan_pointer(string_addrs[i], false);
            if (ptrs !is null)
            {
                dbg("find_string_refs:   -> " + ptrs.length() + " pointer refs");
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
            dbg("find_string_refs: scanning pointers to wide match[" + i + "] @ " + to_hex(wstring_addrs[i]));
            array<uint64>@ ptrs = g_proc.scan_pointer(wstring_addrs[i], false);
            if (ptrs !is null)
            {
                dbg("find_string_refs:   -> " + ptrs.length() + " pointer refs");
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
    dbg("find_string_refs: done, " + refs.length() + " total refs");
}

// ─── Unicorn Emulation ──────────────────────────────────────────────

void cmd_emulate_code(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }

    uint64 code_addr = parse_hex(get_dict_string(req, "code_address"));
    uint code_size = uint(get_dict_double(req, "code_size"));
    uint entry_offset = uint(get_dict_double(req, "entry_offset", 0));
    uint max_insts = uint(get_dict_double(req, "max_instructions", 10000));
    dbg("emulate_code: code_addr=" + to_hex(code_addr) + " code_size=" + code_size + " entry_offset=" + entry_offset + " max_insts=" + max_insts);

    array<uint8> code;
    g_proc.rvm(code_addr, code_size, code);
    if (code.length() == 0) { dbg("emulate_code: read failed"); res.set("error", "failed to read code"); return; }
    dbg("emulate_code: read " + code.length() + " bytes");

    uint64 uc = uc_create();
    if (uc == 0) { dbg("emulate_code: uc_create failed"); res.set("error", "uc_create failed"); return; }
    dbg("emulate_code: uc_create OK handle=" + uc);

    uint64 map_addr = 0x10000;
    uint64 map_size = ((code_size + 0xFFF) & ~0xFFF);
    dbg("emulate_code: mapping code at " + to_hex(map_addr) + " size=" + to_hex(map_size));
    if (!uc_mem_map(uc, map_addr, map_size, UC_PROT_ALL))
    {
        uc_close(uc);
        dbg("emulate_code: uc_mem_map failed");
        res.set("error", "uc_mem_map failed");
        return;
    }
    uc_mem_write(uc, map_addr, code);

    uint64 stack_base = 0x100000;
    uint64 stack_size = 0x10000;
    uint64 stop_addr = 0xDEAD0000;
    dbg("emulate_code: setting up stack at " + to_hex(stack_base) + " stop=" + to_hex(stop_addr));
    if (!uc_setup_stack(uc, stack_base, stack_size, stop_addr))
    {
        uc_close(uc);
        dbg("emulate_code: uc_setup_stack failed");
        res.set("error", "uc_setup_stack failed");
        return;
    }

    array<dictionary@>@ map_regions;
    if (req.get("map_regions", @map_regions) && map_regions !is null)
    {
        dbg("emulate_code: mapping " + map_regions.length() + " extra regions");
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
                dbg("emulate_code:   mapped " + to_hex(aligned_addr) + " size=" + to_hex(aligned_size));
            }
        }
    }

    dictionary@ regs;
    if (req.get("registers", @regs) && regs !is null)
    {
        array<string> reg_names = regs.getKeys();
        dbg("emulate_code: setting " + reg_names.length() + " registers");
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
            {
                uc_reg_write64(uc, reg_id, val);
                dbg("emulate_code:   " + rn + " = " + to_hex(val));
            }
        }
    }

    uint64 start_addr = map_addr + entry_offset;
    dbg("emulate_code: starting emulation at " + to_hex(start_addr));
    bool emu_ok = uc_start(uc, start_addr, stop_addr, 0, max_insts) != 0;
    dbg("emulate_code: uc_start returned emu_ok=" + emu_ok);

    res.set("success", emu_ok);

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
    dbg("emulate_code: rax=" + to_hex(uc_reg_read64(uc, UC_X86_REG_RAX)) + " rip=" + to_hex(uc_reg_read64(uc, UC_X86_REG_RIP)));

    int exc = uc_get_last_exception(uc);
    if (exc != 0)
    {
        res.set("exception", double(exc));
        res.set("exception_address", to_hex(uc_get_exception_address(uc)));
        dbg("emulate_code: EXCEPTION code=" + exc + " at " + to_hex(uc_get_exception_address(uc)));
    }

    uc_close(uc);
    dbg("emulate_code: done");
}

// ─── Assemble ────────────────────────────────────────────────────────

void cmd_assemble(dictionary &in req, dictionary &inout res)
{
    dbg("assemble: not implemented, use write_memory or emulate_code");
    res.set("error", "use write_memory with pre-assembled hex bytes, or emulate_code for execution");
}

// ─── Hex Dump ────────────────────────────────────────────────────────

void cmd_hex_dump(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint size = uint(get_dict_double(req, "size", 256));
    if (size > 4096) size = 4096;
    dbg("hex_dump: addr=" + to_hex(addr) + " size=" + size);

    array<uint8> data;
    g_proc.rvm(addr, size, data);
    if (data.length() == 0) { dbg("hex_dump: read failed"); res.set("error", "read failed"); return; }

    string dump = "";
    for (uint i = 0; i < data.length(); i += 16)
    {
        dump += to_hex(addr + i) + ": ";
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
    dbg("hex_dump: OK " + data.length() + " bytes");
}

// ─── CS2 Specific ───────────────────────────────────────────────────

void cmd_cs2_get_interface(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 mod_base = parse_hex(get_dict_string(req, "module_base"));
    string iface_name = get_dict_string(req, "interface_name");
    dbg("cs2_get_interface: mod=" + to_hex(mod_base) + " name='" + iface_name + "'");
    uint64 addr = g_proc.cs2_get_interface(mod_base, iface_name);
    if (addr != 0)
    {
        res.set("address", to_hex(addr));
        dbg("cs2_get_interface: found at " + to_hex(addr));
    }
    else
    {
        dbg("cs2_get_interface: not found");
        res.set("error", "interface not found");
    }
}

void cmd_cs2_schema_dump(dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    dbg("cs2_schema_dump");
    array<dictionary@>@ schema = g_proc.cs2_get_schema_dump();
    if (schema is null) { dbg("cs2_schema_dump: FAILED"); res.set("error", "schema dump failed"); return; }
    dbg("cs2_schema_dump: got " + schema.length() + " entries");

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
    dbg("cs2_schema_dump: OK " + output.length() + " entries");
}

// ─── Scan Heap Regions ───────────────────────────────────────────────

void cmd_scan_heap_regions(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }

    string regions_csv  = get_dict_string(req, "regions_csv");
    string type         = get_dict_string(req, "type", "u64");
    uint   max_results  = uint(get_dict_double(req, "max_results", 100));
    if (max_results == 0 || max_results > 5000) max_results = 100;

    if (regions_csv == "") { res.set("error", "missing regions_csv"); return; }
    dbg("scan_heap_regions: type=" + type + " max_results=" + max_results + " csv_len=" + regions_csv.length());

    bool   is_u64 = (type == "u64" || type == "pointer");
    bool   is_u32 = (type == "u32");
    if (!is_u64 && !is_u32) { res.set("error", "type must be u32/u64/pointer"); return; }

    uint   val_size = is_u64 ? 8 : 4;
    uint64 u64_val  = 0;
    uint   u32_val  = 0;
    if (is_u64)
        u64_val = parse_hex(get_dict_string(req, "value"));
    else
    {
        double dv; req.get("value", dv);
        u32_val = uint(dv);
    }
    dbg("scan_heap_regions: searching for " + (is_u64 ? to_hex(u64_val) : "" + u32_val));

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

        uint read_sz = uint(r_size < 16 * 1024 * 1024 ? r_size : 16 * 1024 * 1024);
        array<uint8> data;
        g_proc.rvm(r_start, read_sz, data);
        if (data.length() < val_size) continue;
        total_regions++;
        total_bytes += data.length();

        if (total_regions % 50 == 0)
            dbg("scan_heap_regions: scanned " + total_regions + " regions, found=" + found.length());

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
    dbg("scan_heap_regions: done. found=" + found.length() + " regions=" + total_regions + " bytes=" + total_bytes);
}

// ─── Read And Filter Pointers ────────────────────────────────────────

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
    dbg("read_and_filter_pointers: base=" + to_hex(base) + " count=" + count + " stride=" + stride + " vtable_check=" + to_hex(vtable_check));

    array<dictionary@> matches;

    for (uint i = 0; i < count; i++)
    {
        uint64 ptr_addr = base + uint64(i) * stride;
        uint64 ptr      = g_proc.ru64(ptr_addr);
        if (ptr == 0) continue;

        uint64 check_val = g_proc.ru64(ptr + deref_offset);
        if (check_val != vtable_check) continue;

        dbg("read_and_filter_pointers: match[" + matches.length() + "] index=" + i + " ptr=" + to_hex(ptr));
        dictionary m;
        m.set("index",       double(i));
        m.set("ptr_address", to_hex(ptr_addr));
        m.set("pointer",     to_hex(ptr));
        matches.insertLast(@m);
    }

    res.set("matches", @matches);
    res.set("count",   double(matches.length()));
    dbg("read_and_filter_pointers: done " + matches.length() + " matches");
}

// ─── Composite Tools ────────────────────────────────────────────────

void cmd_analyze_object(dictionary &in req, dictionary &inout res)
{
    if (!g_attached || !g_proc.alive()) { res.set("error", "not attached"); return; }
    uint64 addr = parse_hex(get_dict_string(req, "address"));
    uint dump_size = uint(get_dict_double(req, "size", 256));
    if (dump_size > 8192) dump_size = 8192;

    uint vtable_max       = uint(get_dict_double(req, "vtable_max", 16));
    bool vtable_disasm    = get_dict_bool(req, "vtable_disasm");
    uint deref_depth      = uint(get_dict_double(req, "deref_depth", 1));
    uint field_stride     = uint(get_dict_double(req, "stride", 8));
    if (field_stride != 4 && field_stride != 8) field_stride = 8;
    bool read_strings     = get_dict_bool(req, "read_strings", true);
    bool read_wstrings    = get_dict_bool(req, "read_wstrings");
    uint string_max       = uint(get_dict_double(req, "string_max", 128));
    bool skip_rtti        = get_dict_bool(req, "skip_rtti");
    bool skip_vtable      = get_dict_bool(req, "skip_vtable");
    bool skip_fields      = get_dict_bool(req, "skip_fields");
    uint field_offset     = uint(get_dict_double(req, "field_offset", 0));
    bool include_hex_dump = get_dict_bool(req, "hex_dump");
    bool follow_pointers  = get_dict_bool(req, "follow_pointers");

    dbg("analyze_object: addr=" + to_hex(addr) + " size=" + dump_size + " vtable_max=" + vtable_max + " stride=" + field_stride);
    dbg("analyze_object: skip_rtti=" + skip_rtti + " skip_vtable=" + skip_vtable + " skip_fields=" + skip_fields + " hex_dump=" + include_hex_dump);

    uint64 vtable_ptr = g_proc.ru64(addr);
    res.set("vtable_ptr", to_hex(vtable_ptr));
    dbg("analyze_object: vtable_ptr=" + to_hex(vtable_ptr));

    if (!skip_rtti && vtable_ptr > 0x10000 && g_proc.is_valid_address(vtable_ptr))
    {
        dbg("analyze_object: reading RTTI...");
        uint64 rtti_ptr = g_proc.ru64(vtable_ptr - 8);
        dbg("analyze_object: rtti_ptr=" + to_hex(rtti_ptr));
        if (rtti_ptr != 0 && g_proc.is_valid_address(rtti_ptr))
        {
            uint64 type_desc_ptr = g_proc.ru64(rtti_ptr + 16);
            if (type_desc_ptr != 0 && g_proc.is_valid_address(type_desc_ptr))
            {
                string class_name = g_proc.rs(type_desc_ptr + 16, 256);
                if (class_name.length() > 0)
                {
                    res.set("class_name", class_name);
                    dbg("analyze_object: class_name='" + class_name + "'");
                }
            }

            int32 num_base = g_proc.r32(rtti_ptr + 8);
            uint64 base_arr_ptr = g_proc.ru64(rtti_ptr + 24);
            dbg("analyze_object: num_base=" + num_base + " base_arr_ptr=" + to_hex(base_arr_ptr));
            if (num_base > 1 && num_base < 32 && base_arr_ptr != 0 && g_proc.is_valid_address(base_arr_ptr))
            {
                array<string> bases;
                for (int b = 1; b < num_base; b++)
                {
                    uint64 base_desc = g_proc.ru64(base_arr_ptr + uint64(b) * 8);
                    if (base_desc == 0 || !g_proc.is_valid_address(base_desc)) break;
                    uint64 base_td = g_proc.ru64(base_desc);
                    if (base_td != 0 && g_proc.is_valid_address(base_td))
                    {
                        string bn = g_proc.rs(base_td + 16, 256);
                        if (bn.length() > 0)
                        {
                            bases.insertLast(bn);
                            dbg("analyze_object:   base[" + (b-1) + "]='" + bn + "'");
                        }
                    }
                }
                if (bases.length() > 0)
                    res.set("base_classes", bases);
            }
        }
    }

    if (!skip_vtable && vtable_ptr > 0x10000 && g_proc.is_valid_address(vtable_ptr))
    {
        dbg("analyze_object: enumerating vtable (max=" + vtable_max + ")...");
        array<dictionary@> vtable_entries;
        for (uint i = 0; i < vtable_max; i++)
        {
            uint64 fn = g_proc.ru64(vtable_ptr + uint64(i) * 8);
            if (fn == 0 || !g_proc.is_valid_address(fn)) { dbg("analyze_object:   vtable ends at slot " + i); break; }
            dbg("analyze_object:   vtable[" + i + "] = " + to_hex(fn));

            dictionary vte;
            vte.set("index", double(i));
            vte.set("address", to_hex(fn));

            if (vtable_disasm)
            {
                array<uint8> code;
                g_proc.rvm(fn, 64, code);
                if (code.length() > 0)
                {
                    array<dictionary@> insts;
                    zydis_disasm(code, fn, insts);
                    uint limit = insts.length() < 5 ? insts.length() : 5;
                    array<string> lines;
                    for (uint j = 0; j < limit; j++)
                    {
                        if (insts[j] is null) continue;
                        string text;
                        insts[j].get("text", text);
                        lines.insertLast(text);
                        dbg("    " + text);
                    }
                    vte.set("disasm", lines);
                }
            }
            vtable_entries.insertLast(@vte);
        }
        res.set("vtable", @vtable_entries);
        res.set("vtable_count", double(vtable_entries.length()));
        dbg("analyze_object: vtable_count=" + vtable_entries.length());
    }

    if (include_hex_dump)
    {
        dbg("analyze_object: reading hex dump...");
        array<uint8> raw;
        g_proc.rvm(addr, dump_size, raw);
        if (raw.length() > 0)
        {
            res.set("hex", bytes_to_hex(raw));
            dbg("analyze_object: hex dump " + raw.length() + " bytes");
        }
    }

    if (!skip_fields)
    {
        dbg("analyze_object: classifying fields (stride=" + field_stride + " count=" + (dump_size/field_stride) + ")...");
        array<dictionary@> fields;
        for (uint off = field_offset; off < dump_size; off += field_stride)
        {
            uint64 val = (field_stride == 8) ? g_proc.ru64(addr + off) : uint64(g_proc.ru32(addr + off));
            dictionary field;
            field.set("offset", to_hex(uint64(off)));
            field.set("raw_hex", to_hex(val));

            if (val == 0)
            {
                field.set("type", "null");
                dbg("  +0x" + to_hex(uint64(off)) + " [null]");
            }
            else if (val > 0x10000 && val < 0x7FFFFFFFFFFF && g_proc.is_valid_address(val))
            {
                uint64 deref = g_proc.ru64(val);
                bool deref_valid = deref > 0x10000 && deref < 0x7FFFFFFFFFFF && g_proc.is_valid_address(deref);

                if (deref_valid)
                    field.set("type", "pointer");
                else
                    field.set("type", "pointer_leaf");

                field.set("deref", to_hex(deref));
                dbg("  +0x" + to_hex(uint64(off)) + " [ptr] " + to_hex(val) + " -> " + to_hex(deref));

                if (read_strings)
                {
                    uint8 b0 = g_proc.ru8(val);
                    if (b0 >= 0x20 && b0 < 0x7F)
                    {
                        string s = g_proc.rs(val, string_max);
                        if (s.length() >= 2)
                        {
                            field.set("as_string", s);
                            dbg("    as_string='" + s.substr(0, 64) + "'");
                        }
                    }
                }
                if (read_wstrings)
                {
                    uint16 w0 = g_proc.ru16(val);
                    if (w0 >= 0x20 && w0 < 0x7F00)
                    {
                        string ws_val = g_proc.rws(val, string_max);
                        if (ws_val.length() >= 2)
                        {
                            field.set("as_wstring", ws_val);
                            dbg("    as_wstring='" + ws_val.substr(0, 64) + "'");
                        }
                    }
                }

                if (follow_pointers && deref_valid && deref_depth > 1)
                {
                    array<string> chain;
                    chain.insertLast(to_hex(deref));
                    uint64 curr = deref;
                    for (uint d = 1; d < deref_depth; d++)
                    {
                        uint64 next = g_proc.ru64(curr);
                        if (next == 0 || !g_proc.is_valid_address(next)) break;
                        chain.insertLast(to_hex(next));
                        curr = next;
                    }
                    if (chain.length() > 1)
                        field.set("pointer_chain", chain);
                }

                if (follow_pointers && deref_valid)
                {
                    uint64 sub_vtable = g_proc.ru64(val);
                    if (sub_vtable > 0x10000 && g_proc.is_valid_address(sub_vtable))
                    {
                        uint64 sub_rtti = g_proc.ru64(sub_vtable - 8);
                        if (sub_rtti != 0 && g_proc.is_valid_address(sub_rtti))
                        {
                            uint64 sub_td = g_proc.ru64(sub_rtti + 16);
                            if (sub_td != 0 && g_proc.is_valid_address(sub_td))
                            {
                                string cn = g_proc.rs(sub_td + 16, 128);
                                if (cn.length() > 0)
                                {
                                    field.set("rtti_name", cn);
                                    dbg("    rtti_name='" + cn + "'");
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                float f = g_proc.rf32(addr + off);
                double d = g_proc.rf64(addr + off);
                bool likely_float = (f > -1e10 && f < 1e10 && f != 0.0f && (f > 0.001f || f < -0.001f));
                bool likely_double = (d > -1e15 && d < 1e15 && d != 0.0 && (d > 0.001 || d < -0.001));

                if (likely_float)
                {
                    field.set("type", "float_or_int");
                    field.set("as_float", double(f));
                    dbg("  +0x" + to_hex(uint64(off)) + " [float] " + f);
                }
                else if (likely_double)
                {
                    field.set("type", "double_or_int");
                    field.set("as_double", d);
                    dbg("  +0x" + to_hex(uint64(off)) + " [double] " + d);
                }
                else
                {
                    field.set("type", "integer");
                    dbg("  +0x" + to_hex(uint64(off)) + " [int] " + to_hex(val));
                }
                field.set("as_u32", double(uint(val & 0xFFFFFFFF)));
                field.set("as_i32", double(int(val & 0xFFFFFFFF)));
            }
            fields.insertLast(@field);
        }
        res.set("fields", @fields);
        res.set("field_count", double(fields.length()));
        dbg("analyze_object: field_count=" + fields.length());
    }
    dbg("analyze_object: done");
}

// ─── Batch Command Handler ──────────────────────────────────────────

void dispatch_command(const string &in cmd, dictionary &in req, dictionary &inout res)
{
    dbg("dispatch: '" + cmd + "'");
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
    else if (cmd == "analyze_object")      cmd_analyze_object(req, res);
    else
    {
        dbg("dispatch: UNKNOWN command '" + cmd + "'");
        res.set("error", "unknown command: " + cmd);
    }
    dbg("dispatch: '" + cmd + "' done");
}

void cmd_batch(dictionary &in req, dictionary &inout res)
{
    array<dictionary@>@ commands;
    if (!req.get("commands", @commands) || commands is null)
    {
        res.set("error", "batch requires 'commands' array");
        return;
    }
    dbg("batch: " + commands.length() + " commands");

    array<dictionary@> results;
    for (uint i = 0; i < commands.length(); i++)
    {
        if (commands[i] is null) continue;
        string sub_cmd = get_dict_string(commands[i], "cmd");
        dbg("batch[" + i + "]: '" + sub_cmd + "'");
        dictionary sub_res;
        dispatch_command(sub_cmd, commands[i], sub_res);
        results.insertLast(@sub_res);
    }
    res.set("results", @results);
    res.set("count", double(results.length()));
    dbg("batch: done " + results.length() + " results");
}

// ─── Request Router ──────────────────────────────────────────────────

void handle_request(dictionary &in req)
{
    string cmd;
    if (!req.get("cmd", cmd)) { dbg("handle_request: missing 'cmd' field"); return; }

    string req_id;
    req.get("_id", req_id);
    dbg("handle_request: cmd='" + cmd + "' id='" + req_id + "'");

    dictionary res;
    if (req_id != "")
        res.set("_id", req_id);

    if (cmd == "batch")
        cmd_batch(req, res);
    else
        dispatch_command(cmd, req, res);

    send_response(res);
    dbg("handle_request: response sent for '" + cmd + "'");
}

// ─── WebSocket Pump ──────────────────────────────────────────────────

int g_idle_ticks = 0;
const int KEEPALIVE_INTERVAL = 30;

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
            if (msg.findFirst("_hub_ping") >= 0) { g_idle_ticks = 0; break; }

            dbg("RECV: " + msg.substr(0, 200) + (msg.length() > 200 ? "...[" + msg.length() + " chars]" : ""));
            dictionary req;
            string err;
            if (json_parse(msg, req, err))
                handle_request(req);
            else
            {
                dbg("JSON parse error: " + err + " for msg: " + msg.substr(0, 100));
                log_error("JSON parse error: " + err);
            }
            g_idle_ticks = 0;
        }
        if (is_closed) break;
    }

    if (is_closed)
    {
        do_disconnect("MCP disconnected (clean close)");
        return;
    }

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
        log_console("[RE Server DEBUG] Connected to MCP server. RE tools available + DEBUG logging ON.");
    }
    else
    {
        g_ws.close();
        g_ws = ws_t();
        g_retry_count++;
        if (g_retry_count == 1 || g_retry_count % 10 == 0)
            log_console("[RE Server DEBUG] Waiting for MCP server... (attempt " + g_retry_count + ")");
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
    log_console("[RE Server DEBUG] Starting — ALL operations will be printed to console.");
    log_console("[RE Server DEBUG] Will connect to ws://127.0.0.1:9001");

    g_callback_id = register_callback(ws_callback, 1, 0);
    if (g_callback_id == 0)
    {
        log_error("[RE Server DEBUG] Failed to register callback");
        return -1;
    }

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
    log_console("[RE Server DEBUG] Unloaded");
}
