#This script labels Go stripped binaries in Ghidra based on GoReSym output.
#Script requests GoReSym json output file and uses its results to rename
#user functions (including standard functions if available) and labels
#runtime_pclntab and runtime_firstmoduledata based on TabMeta.VA and ModuleMeta.VA.
#Script was tested and works with both Jython/Python2.7 in Ghidra and Python3 in Ghidratron.
#@category Analysis

from ghidra.program.model.symbol import SourceType

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

# Perform labeling
rename_funcs(hints["UserFunctions"], offset)
rename_funcs(hints["StdFunctions"], offset)
annotate(hints["Interfaces"], 0)
annotate([
    {"VA": hints["TabMeta"]["VA"], "Str": "runtime_pclntab"},
    {"VA": hints["ModuleMeta"]["VA"], "Str": "runtime_firstmoduledata"}
], 0)
