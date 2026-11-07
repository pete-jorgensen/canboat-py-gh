import json
import keyword
import os
import re
from jinja2 import Environment, FileSystemLoader

# Load the JSON data
with open("canboat.json") as f:
    json_data = json.load(f)

# The canboat JSON export can omit RangeMin for an unsigned wrapping field
# (e.g. the Garmin autopilot full-circle turn angles); the decode templates
# require both bounds, and 0.0 is the unsigned minimum.
for _pgn in json_data.get("PGNs", []):
    for _field in _pgn.get("Fields", []):
        if "RangeMax" in _field and "RangeMin" not in _field and not _field.get("Signed"):
            _field["RangeMin"] = 0.0

# The canboat JSON export omits Resolution when it is exactly 1; the keyed
# (DYNAMIC_FIELD_VALUE) decode path uses a missing resolution to mean "opaque
# bytes", so make the implied default explicit for numeric keyed entries.
for _enum in json_data.get("LookupFieldTypeEnumerations", []):
    for _entry in _enum.get("EnumFieldTypeValues", []):
        if _entry.get("FieldType") in ("NUMBER", "TIME") and "Resolution" not in _entry:
            _entry["Resolution"] = 1


def bits_to_hex(len: int) -> str:
    num = 0
    for i in range(len):
        num = (num << 1) ^ 1
    return f"0x{num:X}"


def generate_field_id(field_id, field_type, field_offset):
    if field_type == "RESERVED":
        return "reserved_" + str(field_offset)
    return field_id


pattern = r"[^a-zA-Z0-9]"


def generate_field_python_name(field_name, field_type, field_offset):
    if field_type == "RESERVED":
        return "reserved_" + str(field_offset)
    temp = re.sub(pattern, "_", field_name).lower()
    if temp[0].isdigit() or keyword.iskeyword(temp):
        temp = "__" + temp
    return temp


# Set up the Jinja2 environment
file_loader = FileSystemLoader(searchpath="./")
env = Environment(loader=file_loader, extensions=["jinja2.ext.loopcontrols"])
env.globals["bits_to_hex"] = bits_to_hex
env.globals["generate_field_id"] = generate_field_id
env.globals["generate_field_python_name"] = generate_field_python_name


# Emit a DB-sourced string (Name/Unit/Description) as a safe Python string literal,
# preserving the historical quote style so output is byte-identical for any string
# without that quote or a backslash; only escapes when a value actually contains the
# quote char or a backslash (e.g. "Ship's width").
def pylit(s, quote="'"):
    s = str(s).replace("\\", "\\\\").replace(quote, "\\" + quote)
    return f"{quote}{s}{quote}"


env.filters["pylit"] = pylit

# Load the Jinja2 template
template = env.get_template("python.consts.j2")

# Render the template with the JSON data
output = template.render(data=json_data)

# Save the generated Python code to a file
with open(os.path.join("nmea2000", "consts.py"), "w") as f:
    f.write(output)

# Load the Jinja2 template
template = env.get_template("python.PGNs.j2")

# Render the template with the JSON data
output = template.render(data=json_data)

# Save the generated Python code to a file
with open(os.path.join("nmea2000", "pgns.py"), "w") as f:
    f.write(output)

print("Python code generated successfully!")
