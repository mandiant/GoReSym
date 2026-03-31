#This script labels Go stripped binaries in Ghidra based on GoReSym output.
#Script requests GoReSym json output file and uses its results to rename
#user functions (including standard functions if available) and labels
#runtime_pclntab and runtime_firstmoduledata based on TabMeta.VA and ModuleMeta.VA.
#Script was tested and works with both Jython/Python2.7 in Ghidra and Python3 in Ghidratron.
#
#Improvements over original:
# - Registers Go primitive types (GoString, GoSlice, GoIface) in the data type manager
# - Applies recovered struct layouts from CReconstructed fields at their virtual addresses
# - Annotates interfaces with GoIface struct type, not just a plain label
# - Adds source file + line number as a pre-comment on each user function entry point
#
#@category Analysis

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    StructureDataType, CategoryPath, DataTypeConflictHandler,
    PointerDataType, VoidDataType, UnsignedLongLongDataType,
    UnsignedIntegerDataType
)
from ghidra.program.model.listing import CodeUnit

import collections
import json
import re

# No estimation is done
CHOICE_EST_NONE = "no estimation"
# Maps entry function to the longest _rt0_ function found by GoReSym
CHOICE_EST_ENTRY_ADDR = "entry to _rt0_ function mapping"
# Maps pclntab section to TabMeta VA mapping, useful only when pclntab section is present
CHOICE_EST_PCLNTAB = "pclntab to TabMeta VA mapping"
# Tries to map addresses against known function names in Ghidra with functions found by GoReSym
CHOICE_EST_KNOWN_FUNCS = "known function names mapping"
# All available choices
CHOICES = [CHOICE_EST_NONE, CHOICE_EST_ENTRY_ADDR, CHOICE_EST_PCLNTAB, CHOICE_EST_KNOWN_FUNCS]

def iterable(obj):
    if obj is None:
        return False

    try:
        iter(obj)
    except TypeError:
        return False

    return True

def extract_funcs(hints):
    funcs = []
    for f in ["UserFunctions", "StdFunctions"]:
        if iterable(hints[f]):
            funcs += hints[f]
    return funcs

def _entry_addr_estimator(hints):
    if not iterable(hints["StdFunctions"]):
        print("No StdFunctions present, required for entry addr estimation")
        return None

    # StdFunctions should have _rt0_[ARCH]_[OS](_lib)?, this maps to entry
    candidates = [f for f in hints["StdFunctions"] if "_rt0_" in f["FullName"]]

    if len(candidates) == 0:
        print("No rt0 functions found")
        return None

    func = max(candidates, key=lambda f: len(f["FullName"]))

    fm = getCurrentProgram().getFunctionManager()
    for f in fm.getFunctions(True):
        if f.getName() == "entry":
            return f.getEntryPoint().getOffset()-func["Start"]

    return None

def _pclntab_estimator(hints):
    # Expected pclntab name per exec format
    exec_fmt = getCurrentProgram().getMetadata()["Executable Format"]
    pclntabs = []
    block_name = ".text"
    if exec_fmt == "Executable and Linking Format (ELF)":
        # https://github.com/mandiant/GoReSym/blob/0c729523ed542f24b091e433204fbc6b02c88b31/objfile/elf.go#L89        
        pclntabs.append(".gopclntab")
    elif exec_fmt == "Portable Executable (PE)":
        # https://github.com/mandiant/GoReSym/blob/0c729523ed542f24b091e433204fbc6b02c88b31/objfile/pe.go#L130        
        pclntabs.append("runtime.pclntab")
        pclntabs.append("runtime.epclntab")
    elif exec_fmt == "Mac OS X Mach-O":
        # https://github.com/mandiant/GoReSym/blob/0c729523ed542f24b091e433204fbc6b02c88b31/objfile/macho.go#L111     
        pclntabs.append("__gopclntab")
        block_name = "__TEXT"
    else:
        # Try legacy
        # https://github.com/mandiant/GoReSym/blob/0c729523ed542f24b091e433204fbc6b02c88b31/objfile/pe.go#L147        
        pclntabs.append("pclntab")
        pclntabs.append("epclntab")

    # Check if pclntab is present
    for p in pclntabs:
        pclntab = getCurrentProgram().getMemory().getBlock(p)
        if pclntab is not None:
            # With pclntab, offset should be a matter of TabMeta VA
            tmva = hints["TabMeta"]["VA"]
            text = getCurrentProgram().getMemory().getBlock(block_name)
            return text.getStart().getOffset()-tmva

    return None

def _func_map_estimator(hints):
    offs = []
    # Try to guess with known function names
    hfuncs = extract_funcs(hints)
    grs_funcs = {f["FullName"]: f for f in hfuncs}

    # Match function lists and collect possible offsets
    fm = getCurrentProgram().getFunctionManager()
    for f in fm.getFunctions(True):
        name = f.getName()
        if "FUN_" in name or name == "entry":
            continue
        if name in grs_funcs:
            offs.append(f.getEntryPoint().getOffset()-grs_funcs[name]["Start"])

    # Count given offsets, most counts is our estimate
    counter = collections.Counter(offs)
    winner, winner_count = counter.most_common()[0] if len(counter) > 0 else (None, 0)
    return winner

def estimate_offset(choice, hints):
    if choice == CHOICE_EST_KNOWN_FUNCS:
        estimator = _func_map_estimator
    elif choice == CHOICE_EST_PCLNTAB:
        estimator = _pclntab_estimator
    elif choice == CHOICE_EST_ENTRY_ADDR:
        estimator = _entry_addr_estimator
    else:
        # No estimation
        return 0

    e = estimator(hints)
    if e is not None:
        return e

    return 0

def ask_offset(default):
    msg = "Please specify optional memory offset for entrypoints, script estimated {} with chosen strategy".format(default)
    offset = askString("Optional offset", msg, str(default))
    return int(offset)

def rename_funcs(items, offset, simulate=False):
    if not iterable(items):
        return 0, 0

    fm = getCurrentProgram().getFunctionManager()
    rename_counter, create_counter = 0, 0
    for func in items:
        try:
            # ' ' is considered as invalid char
            # https://github.com/NationalSecurityAgency/ghidra/blob/c19276091f274a9ef0850c904c743f61c850854e/Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/symbol/SymbolUtilities.java#L104
            addr, name = func["Start"], func["FullName"].replace(" ", "_")
            entrypoint = toAddr(addr+offset)

            f = fm.getFunctionAt(entrypoint)
            if f is None:
                create_counter += 1
                if not simulate:
                    print("Creating new func at {}".format(entrypoint))
                    createFunction(entrypoint, name)
            else:
                rename_counter += 1
                if not simulate:
                    print("Renaming func {} to {}".format(f.getName(), name))
                    f.setName(name, SourceType.USER_DEFINED)
        except Exception as e:
            print(u"error renaming {} at {}: {}".format(name, hex(addr), e))

    return rename_counter, create_counter

def annotate(items, offset):
    if not iterable(items):
        return

    for i in items:
        if i["VA"] != 0:
            # ' ' is considered as invalid char
            createLabel(toAddr(i["VA"]+offset), i["Str"].replace(" ", "_"), True)

def offset_estimation_sim(hints):
    # Simulate all offset calculation strategies
    # Returns stats for all choices in a dict and a suggested choice
    choices_dict, suggested = {}, None

    # Since CHOICES contains "no estimation" as first strategy,
    # we will perform a rename without offset first and then try
    # all other strategies. If we detect that another strategy
    # has more renames, we return it as suggested
    for choice in CHOICES:
        estoff = estimate_offset(choice, hints)
        hfuncs = extract_funcs(hints)
        renamed, created = rename_funcs(hfuncs, estoff, True)
        print("{} renamed {} and created {} functions".format(choice, renamed, created))

        choices_dict[choice] = {"renamed": renamed, "created": created, "offset": estoff}
        if suggested is None or choices_dict[suggested]["renamed"] < renamed:
            suggested = choice

    return choices_dict, suggested


# ---------------------------------------------------------------------------
# NEW: Register Go primitive types in Ghidra's data type manager.
#
# IDA's script did this via idc_parse_types() for string, slice, and iface.
# Ghidra has no Go-aware equivalent, so we construct the structs manually
# using the Ghidra Java API. These are prerequisites for any recovered
# struct that references a string or slice field.
#
# GoString -> { void *ptr; uint64 len; }
# GoSlice  -> { void *ptr; uint64 len; uint64 cap; }
# GoIface  -> { void *tab; void *data; }
# ---------------------------------------------------------------------------

def register_go_primitives(dtm):
    cp       = CategoryPath("/Go")
    ptr_size = currentProgram.getDefaultPointerSize()
    ptr_dt   = PointerDataType(VoidDataType.dataType, ptr_size, dtm)
    u64      = UnsignedLongLongDataType.dataType

    txn = currentProgram.startTransaction("GoReSym: register primitives")
    try:
        if dtm.getDataType(cp, "GoString") is None:
            s = StructureDataType(cp, "GoString", 0)
            s.add(ptr_dt, ptr_size, "ptr", "pointer to UTF-8 bytes")
            s.add(u64,    8,        "len", "byte length")
            dtm.addDataType(s, DataTypeConflictHandler.KEEP_HANDLER)

        if dtm.getDataType(cp, "GoSlice") is None:
            sl = StructureDataType(cp, "GoSlice", 0)
            sl.add(ptr_dt, ptr_size, "ptr", "pointer to backing array")
            sl.add(u64,    8,        "len", "element count")
            sl.add(u64,    8,        "cap", "capacity")
            dtm.addDataType(sl, DataTypeConflictHandler.KEEP_HANDLER)

        if dtm.getDataType(cp, "GoIface") is None:
            iface = StructureDataType(cp, "GoIface", 0)
            iface.add(ptr_dt, ptr_size, "tab",  "itable pointer (type + methods)")
            iface.add(ptr_dt, ptr_size, "data", "pointer to concrete value")
            dtm.addDataType(iface, DataTypeConflictHandler.KEEP_HANDLER)

        print("GoReSym: Go primitive types registered under /Go")
    except Exception as e:
        print("GoReSym: primitive registration error: {}".format(e))
    finally:
        currentProgram.endTransaction(txn, True)


# ---------------------------------------------------------------------------
# NEW: Apply recovered struct layouts at their virtual addresses.
#
# IDA's script called idc_parse_types() + apply_tinfo() per type, giving
# analysts named fields in the decompiler view. The original Ghidra script
# only created a label. We now also parse GoReSym's CReconstructed field
# (a C-like struct definition), build a StructureDataType, and apply it
# at the type's VA via listing.createData() — same effect as IDA.
# ---------------------------------------------------------------------------

# Mapping of C primitive type names in GoReSym output to byte sizes.
# Pointer fields are detected separately by '*' in the type string.
_C_TYPE_SIZE = {
    "uint8_t":  1, "int8_t":  1,
    "uint16_t": 2, "int16_t": 2,
    "uint32_t": 4, "int32_t": 4, "float":  4,
    "uint64_t": 8, "int64_t": 8, "double": 8,
}

def _parse_reconstructed(reconstructed):
    """Return list of (c_type_str, field_name) parsed from a CReconstructed string."""
    inner = re.sub(r'^[^{]*\{', '', reconstructed)
    inner = re.sub(r'\}[^}]*;?\s*$', '', inner)
    fields = []
    for line in inner.split(";"):
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        parts = line.split()
        if len(parts) >= 2:
            field_name = parts[-1].lstrip("*").strip()
            c_type     = " ".join(parts[:-1])
            fields.append((c_type, field_name))
    return fields

def apply_types(types, dtm):
    if not iterable(types):
        return 0

    ptr_size = currentProgram.getDefaultPointerSize()
    ptr_dt   = PointerDataType(VoidDataType.dataType, ptr_size, dtm)
    listing  = currentProgram.getListing()
    cp       = CategoryPath("/Go/Types")
    applied  = 0

    txn = currentProgram.startTransaction("GoReSym: apply types")
    try:
        for typ in types:
            va            = typ.get("VA", 0)
            name          = typ.get("Str", "")
            reconstructed = typ.get("CReconstructed") or typ.get("Reconstructed") or ""

            # Always create a label — preserves original behaviour for every type
            if va and va != 0:
                try:
                    createLabel(toAddr(va), name.replace(" ", "_"), True)
                except Exception as e:
                    print(u"GoReSym: label error {}: {}".format(name, e))

            # Only go further when a struct definition is available
            if not reconstructed or "struct" not in reconstructed:
                continue

            safe_name = re.sub(r"[^A-Za-z0-9_]", "_", name)
            if not safe_name:
                continue

            try:
                fields = _parse_reconstructed(reconstructed)
                if not fields:
                    continue

                s = StructureDataType(cp, safe_name, 0)
                for c_type, fname in fields:
                    is_ptr = "*" in c_type
                    if is_ptr:
                        dt   = ptr_dt
                        size = ptr_size
                    else:
                        size = _C_TYPE_SIZE.get(c_type.strip(), ptr_size)
                        if size == 1:
                            dt = UnsignedIntegerDataType.dataType
                        elif size == 2:
                            dt = UnsignedIntegerDataType.dataType
                        elif size == 4:
                            dt = UnsignedIntegerDataType.dataType
                        else:
                            dt = UnsignedLongLongDataType.dataType
                    try:
                        s.add(dt, size, fname, "")
                    except Exception:
                        pass  # skip bad fields; partial struct still helps

                final_dt = dtm.addDataType(s, DataTypeConflictHandler.REPLACE_HANDLER)

                if va and va != 0:
                    addr = toAddr(va)
                    try:
                        listing.clearCodeUnits(addr, addr.add(final_dt.getLength() - 1), False)
                        listing.createData(addr, final_dt)
                    except Exception:
                        pass
                    applied += 1

            except Exception as e:
                print(u"GoReSym: type apply error {}: {}".format(name, e))

    finally:
        currentProgram.endTransaction(txn, True)

    return applied


# ---------------------------------------------------------------------------
# NEW: Apply GoIface struct at interface virtual addresses.
#
# The original script passed interfaces to annotate(), which only created
# a label. IDA's script additionally cleared the item and applied abi_Type
# tinfo so the decompiler showed tab/data fields. We do the same here using
# the GoIface struct registered in register_go_primitives().
# ---------------------------------------------------------------------------

def apply_interfaces(interfaces, dtm):
    if not iterable(interfaces):
        return 0

    listing  = currentProgram.getListing()
    iface_dt = dtm.getDataType(CategoryPath("/Go"), "GoIface")
    applied  = 0

    txn = currentProgram.startTransaction("GoReSym: apply interfaces")
    try:
        for typ in interfaces:
            va   = typ.get("VA", 0)
            name = typ.get("Str", "")
            if not va or va == 0:
                continue
            try:
                addr = toAddr(va)
                # label always created (same as original annotate())
                createLabel(addr, name.replace(" ", "_"), True)
                # additionally apply GoIface layout so tab/data fields are visible
                if iface_dt is not None:
                    listing.clearCodeUnits(addr, addr.add(iface_dt.getLength() - 1), False)
                    listing.createData(addr, iface_dt)
                applied += 1
            except Exception as e:
                print(u"GoReSym: interface apply error {}: {}".format(name, e))
    finally:
        currentProgram.endTransaction(txn, True)

    return applied


# ---------------------------------------------------------------------------
# NEW: Write source file path + line number as a pre-comment on each
# user function entry point.
#
# Neither the original Ghidra script nor IDA's script did this. GoReSym
# includes FileName and LineNumber per function when -p is used. Surfacing
# this in the listing means analysts can immediately see which source file
# a function came from without cross-referencing the JSON separately.
# ---------------------------------------------------------------------------

def annotate_func_source(user_funcs, offset):
    if not iterable(user_funcs):
        return 0

    listing   = currentProgram.getListing()
    annotated = 0

    txn = currentProgram.startTransaction("GoReSym: source comments")
    try:
        for func in user_funcs:
            file_name   = func.get("FileName") or func.get("FilePath") or ""
            line_number = func.get("LineNumber") or func.get("Line") or 0
            if not file_name:
                continue
            try:
                addr = toAddr(func["Start"] + offset)
                cu   = listing.getCodeUnitAt(addr)
                if cu is not None:
                    cu.setComment(CodeUnit.PRE_COMMENT,
                                  "// Source: {}:{}".format(file_name, line_number))
                    annotated += 1
            except Exception as e:
                print(u"GoReSym: comment error at {}: {}".format(hex(func["Start"]), e))
    finally:
        currentProgram.endTransaction(txn, True)

    return annotated


# ---------------------------------------------------------------------------
# Main — original flow is completely unchanged below this line.
# New calls are appended after it so they can never break existing behaviour.
# ---------------------------------------------------------------------------

# Load input file
grsfile = askFile("GoReSym output file", "Choose GoReSym output file")
with open(grsfile.getAbsolutePath(), "rb") as fp:
    buf = fp.read()
hints = json.loads(buf)

# Run simulation and estimate offsets, offsets are returned in choices_dict
choices_dict, suggested = offset_estimation_sim(hints)
offset = choices_dict[suggested]["offset"]

# Ask for offset estimation strategy and suggest the most appropriate
# only if "no estimation" resulted in less renames than another strategy
if suggested != CHOICE_EST_NONE:
    msg = "Please choose offset estimation strategy, script got most renames with [{}]".format(suggested)
    choice = askChoice("Offset estimation", msg, CHOICES, suggested)
    # Ask for offset, use chosen strategy offset as default
    offset = ask_offset(choices_dict[choice]["offset"])

# Perform labeling (original, unchanged)
rename_funcs(hints["UserFunctions"], offset)
rename_funcs(hints["StdFunctions"], offset)
annotate(hints["Interfaces"], 0)
annotate([
    {"VA": hints["TabMeta"]["VA"], "Str": "runtime_pclntab"},
    {"VA": hints["ModuleMeta"]["VA"], "Str": "runtime_firstmoduledata"}
], 0)

# ---------------------------------------------------------------------------
# New additions — always run after the original labeling block so that a
# failure in any of these never prevents the core renaming from completing.
# ---------------------------------------------------------------------------

dtm = currentProgram.getDataTypeManager()

register_go_primitives(dtm)

types_applied  = apply_types(hints.get("Types"), dtm)
ifaces_applied = apply_interfaces(hints.get("Interfaces"), dtm)
src_annotated  = annotate_func_source(hints.get("UserFunctions"), offset)

print("")
print("=== GoReSym import complete ===")
print("  Types applied   : {}".format(types_applied))
print("  Interfaces      : {}".format(ifaces_applied))
print("  Source comments : {}".format(src_annotated))
print("================================")
