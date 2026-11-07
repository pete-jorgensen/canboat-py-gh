"""canboat-py's extended structural decode semantics.

Emits decode knowledge canboat's flat field model cannot express, as extra keys
attached to a decoded message (``message.extensions``). Decode-only:
facts/labels only.

Gating: implications + command by ``implications``; annotations + value-notes +
catalog texts by ``annotations``. Default decoders leave all off, so output is
identical to upstream unless a caller opts in.

Emitted keys:
  "<field> Implications" : [{"bit","name","implies":[pgns]}]
  "<field> Command"      : {"kind","action","equivalent"?}
  "<field> Annotation"   : {"type","description"}
  "<field> Note"         : str
  "Action/Long/Short Text" : str  (130822 alert catalog resolution)
"""
from .mercury_fault_catalog import (MERCURY_FAULT_ACTION, MERCURY_FAULT_LONG,
                                    MERCURY_FAULT_SHORT)

# Capability-bit implications. (pgn, field) -> [(bit, name, [implied pgns])]
BIT_IMPLICATIONS = {
    (130829, "Capabilities"): [(0, "Beacon", [130829]), (1, "Cruise Control", [130824])],
}

# Command semantics. (pgn, field) -> {value: (kind, action, equiv|None)}
# equiv = (pgn, family, feature) — feature 0 => family-level.
COMMAND_TABLES = {
    (130825, "Opcode"): {
        0:  ("command", "horn control", None),
        1:  ("command", "maintenance reset", None),
        2:  ("response", "maintenance reset", None),
        4:  ("command", "cruise control", (126720, "cruise", 0x46)),
        5:  ("command", "global brightness", None),
        6:  ("command", "active trim", (126720, "active-trim", 0x28)),
        7:  ("signal", "active trim status", (126720, "active-trim", 0x28)),
        8:  ("command", "autopilot", (126720, "autopilot", 0)),
        9:  ("command", "active exhaust", (126720, "sport-exhaust", 0x2d)),
        12: ("command", "oil level check", (126720, "oil-level", 0x41)),
        13: ("response", "oil level reset", (126720, "oil-level", 0x41)),
    },
}
# 130825 opcode 7 (active trim status) sub-message payload model (opcode-specific bytes
# inside the Data block; per-index value labels are not decoded): byte0 = target
# instance (0xff = broadcast); byte1 = ConfigurationMode / ModuleDetected (tri-state enum);
# byte2 = MajorProfile (u8); byte3 = RunningProfile (u8); byte4 = StatusFlags (u8 bitfield,
# bit0 = Engaged; 0xff = not-available).

# Per-field annotations. (pgn, field) -> (type, description)
ANNOTATIONS = {
    (130826, "Data"): (
        "opaque-external-protocol",
        "Variable-length Mercury BAM (Bridge Alert Management) digital-data payload; "
        "block semantics are defined by an external BAM specification and are not "
        "locally decodable. The BAM message model (IEC 62923) is: heartbeat (repeat "
        "interval, equipment in normal operation); alert command (alert identifier, "
        "alert instance, alert command); acknowledge (alarm number). These name the BAM "
        "message model, not a wire-offset binding for "
        "these frames -- this Data block is the opaque flag-gated float32-block transient "
        "form, distinct from a populated BAM alert sentence."),
    (127501, "Indicator11"): (
        "victron-binary-status",
        "Victron VE.Bus binary-status channel 11 (bank instance 0) = Ripple warning "
        "(high DC-bus ripple); On = warning active."),
}

# Value-conditional notes. (pgn, field) -> {value: note}. Currently empty.
VALUE_NOTES = {}

# 130822 alert catalog resolution. (pgn, index field) -> (out key, 0-based catalog)
CATALOG_TEXTS = {
    (130822, "Action Text Index"): ("Action Text", MERCURY_FAULT_ACTION),
    (130822, "Long Text Index"): ("Long Text", MERCURY_FAULT_LONG),
    (130822, "Short Text Index"): ("Short Text", MERCURY_FAULT_SHORT),
}

# Notes for a keyed (DYNAMIC_FIELD_KEY/VALUE) repeating entry, matched by the resolved key
# NAME. (pgn, key_name) -> note. Attached as the entry's "Value Note". 130824 keys
# 0x1B0/0x1C0/0x1D0 are three DISTINCT cumulative fuel-used (consumption) accumulators
# (lifetime / user-resettable trip / user-resettable season), so a raw 0 is a definitional
# zero (no fuel consumed since that counter's epoch/reset), not missing data or an offset.
_FUEL_USED_NOTE = ("Cumulative fuel-used (consumption) accumulator; 0 is a definitional zero "
                   "(no fuel consumed since this counter's epoch/reset), not missing data.")
KEYED_VALUE_NOTES = {
    (130824, "Engine 0 Fuel Used"): _FUEL_USED_NOTE,
    (130824, "Engine 1 Fuel Used"): _FUEL_USED_NOTE,
    (130824, "Engine 0 Fuel Used Trip"): _FUEL_USED_NOTE,
    (130824, "Engine 1 Fuel Used Trip"): _FUEL_USED_NOTE,
    (130824, "Engine 0 Fuel Used Season"): _FUEL_USED_NOTE,
    (130824, "Engine 1 Fuel Used Season"): _FUEL_USED_NOTE,
}



def _as_note_int(raw_value):
    """An int suitable for a value-note lookup: the int itself, or a short little-endian
    BINARY field's bytes coerced to int (e.g. a 4-bit nibble field decodes to b'\\x0f').
    Returns None for anything else."""
    if isinstance(raw_value, int):
        return raw_value
    if isinstance(raw_value, (bytes, bytearray)) and 0 < len(raw_value) <= 8:
        return int.from_bytes(bytes(raw_value), "little")
    return None


def field_extensions(pgn, name, raw_value, *, implications=True, annotations=True):
    """Extension keys for one decoded field."""
    out = {}
    have = isinstance(raw_value, int)
    if implications and have:
        bits = BIT_IMPLICATIONS.get((pgn, name))
        if bits:
            impl = [{"bit": b, "name": nm, "implies": list(p)}
                    for (b, nm, p) in bits if raw_value & (1 << b)]
            if impl:
                out[f"{name} Implications"] = impl
        table = COMMAND_TABLES.get((pgn, name))
        if table and raw_value in table:
            kind, action, equiv = table[raw_value]
            d = {"kind": kind, "action": action}
            if equiv is not None:
                epgn, fam, feat = equiv
                eq = {"pgn": epgn, "family": fam}
                if feat:
                    eq["feature"] = feat
                d["equivalent"] = eq
            out[f"{name} Command"] = d
    if annotations:
        ann = ANNOTATIONS.get((pgn, name))
        if ann is not None:
            out[f"{name} Annotation"] = {"type": ann[0], "description": ann[1]}
        note = VALUE_NOTES.get((pgn, name))
        if note is not None:
            # value-notes accept a plain int OR a short BINARY field's bytes (e.g. the
            # 130829 Helm/Sub Helm 4-bit nibble fields decode to b'\\x0f').
            nv = _as_note_int(raw_value)
            if nv is not None and nv in note:
                out[f"{name} Note"] = note[nv]
        if have:
            cat = CATALOG_TEXTS.get((pgn, name))
            if cat is not None:
                key, arr = cat
                if 0 < raw_value < len(arr) and arr[raw_value]:
                    out[key] = arr[raw_value]
    return out



# AIS communication state (PGNs 129038/129039/129793): a 19-bit field whose layout
# depends on the message's SOTDMA/ITDMA flag, so canboat's flat model keeps it BINARY
# and the split lives here. ITU-R M.1371: SOTDMA = sync(2) + slot timeout(3) +
# sub-message(14); ITDMA = sync(2) + slot increment(13) + number of slots(3) + keep(1).
_AIS_COMM_STATE_PGNS = (129038, 129039, 129793)
_AIS_SYNC_STATE = {0: "UTC direct", 1: "UTC indirect",
                   2: "Synchronized to a base station", 3: "Synchronized to another station"}


def ais_communication_state(message):
    """The decoded SOTDMA/ITDMA communication state of an AIS message, or None."""
    if message.PGN not in _AIS_COMM_STATE_PGNS:
        return None
    cs = flag = None
    for f in message.fields:
        if f.name == "Communication State" and isinstance(f.raw_value, (bytes, bytearray, int)):
            cs = f.raw_value
        elif f.name == "AIS communication state":
            flag = f.value if f.value is not None else f.raw_value
    if cs is None:
        return None
    v = int.from_bytes(cs, "big") if isinstance(cs, (bytes, bytearray)) else int(cs)
    sync = v & 0x3
    out = {"Sync State": _AIS_SYNC_STATE.get(sync, sync)}
    if flag in ("ITDMA", 1):
        out["Access Scheme"] = "ITDMA"
        out["Slot Increment"] = (v >> 2) & 0x1FFF
        out["Number of Slots"] = (v >> 15) & 0x7
        out["Keep Flag"] = (v >> 18) & 0x1
    else:
        # SOTDMA, and 129793 (UTC/date, message 4) which is always SOTDMA
        out["Access Scheme"] = "SOTDMA"
        out["Slot Time-out"] = (v >> 2) & 0x7
        out["Sub-message"] = (v >> 5) & 0x3FFF
    return out


def apply(message, body=None, *, implications=True, annotations=True):
    """Attach the extended keys to `message.extensions` in place (no-op if nothing
    matches). Call after the message's fields are decoded. `body`, the reassembled
    payload, is accepted and not used."""
    ext = {}
    for f in message.fields:
        ext.update(field_extensions(message.PGN, f.name, f.raw_value,
                                    implications=implications, annotations=annotations))
        # keyed (DYNAMIC_FIELD_KEY/VALUE) repeating entries live in a "##list##" field;
        # attach a note to any entry whose resolved key name has one (e.g. the 130824
        # fuel-used counters' definitional-zero note).
        if annotations and getattr(f, "id", None) == "##list##" and isinstance(f.value, list):
            for entry in f.value:
                kf = entry.get("key") if isinstance(entry, dict) else None
                if kf is None or not isinstance(kf.value, str):
                    continue
                note = KEYED_VALUE_NOTES.get((message.PGN, kf.value))
                if note is not None:
                    ext.setdefault("Keyed Value Notes", {})[kf.value] = note
    if annotations:
        cs = ais_communication_state(message)
        if cs is not None:
            ext["Communication State Decoded"] = cs
    if ext:
        message.extensions = ext
    return message
