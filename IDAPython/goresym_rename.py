# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
import idaapi
import ida_bytes
import ida_kernwin
import ida_name
import json

def iterable(obj):
    if obj is None:
        return False

    try:
        iter(obj)
    except Exception:
        return False
    else:
        return True

hints = ida_kernwin.ask_file(0, "*.*", "GoReSym output file")
with open(hints, "r", encoding="utf-8") as rp:
    buf = rp.read()

hints = json.loads(buf)
if iterable(hints['UserFunctions']):
    for func in hints['UserFunctions']:
        print("Renaming %s to %s" % (hex(func['Start']), func['FullName']))
        idaapi.add_func(func['Start'], func['End'])
        idaapi.set_name(func['Start'], func['FullName'], idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)

if iterable(hints['StdFunctions']):
    for func in hints['StdFunctions']:
        print("Renaming %s to %s" % (hex(func['Start']), func['FullName']))
        idaapi.add_func(func['Start'], func['End'])
        idaapi.set_name(func['Start'], func['FullName'], idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)

if iterable(hints['Types']):
    for typ in hints['Types']:
        print("Renaming %s to %s" % (hex(typ['VA']), typ['Str']))
        idaapi.set_name(typ['VA'], typ['Str'], idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)
        
        # IDA often thinks these are string pointers, lets undefine that, then set the type correctly
        ida_bytes.del_items(typ['VA'], 0, 4)
        py_type = idaapi.idc_parse_decl(idaapi.cvar.idati, "void* ptr;", 1)
        idaapi.apply_type(idaapi.cvar.idati, py_type[1], py_type[2], typ['VA'], idaapi.TINFO_DEFINITE)

if iterable(hints['Interfaces']):
    for typ in hints['Interfaces']:
        print("Renaming %s to %s" % (hex(typ['VA']), typ['Str']))
        idaapi.set_name(typ['VA'], typ['Str'], idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)
        
        # IDA often thinks these are string pointers, lets undefine that, then set the type correctly
        ida_bytes.del_items(typ['VA'], 0, 4)
        py_type = idaapi.idc_parse_decl(idaapi.cvar.idati, "void* ptr;", 1)
        idaapi.apply_type(idaapi.cvar.idati, py_type[1], py_type[2], typ['VA'], idaapi.TINFO_DEFINITE)

if hints['TabMeta'] is not None:
    tabmeta = hints['TabMeta']
    va = tabmeta['VA']
    if va is not None and va != 0:
        idaapi.set_name(va, 'runtime_pclntab', idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)

if hints['ModuleMeta'] is not None:
    modmeta = hints['ModuleMeta']
    va = modmeta['VA']
    if va is not None and va != 0:
        idaapi.set_name(va, 'runtime_firstmoduledata', idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)
