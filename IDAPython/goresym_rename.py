# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_typeinf
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

# https://gist.github.com/NyaMisty/693db2ce2e75c230f36b628fd7610852
# 'Synchonize to idb' right click equivalent
def resync_local_types():
    def is_autosync(name, tif):
        return idaapi.get_ordinal_from_idb_type(name, tif.get_decltype().to_bytes(1, 'little')) != -1

    for ord in range(1, idaapi.get_ordinal_qty(None)):
        t = idaapi.tinfo_t()
        t.get_numbered_type(None, ord)
        typename = t.get_type_name()
        if typename.startswith('#'):
            continue
        
        autosync = is_autosync(typename, t)
        #print('Processing struct %d: %s%s' % (ord, typename, ' (autosync) ' if autosync else ''))
        idaapi.import_type(None, -1, typename, idaapi.IMPTYPE_OVERRIDE)
        if autosync:
            continue
        struc = idaapi.get_struc(idaapi.get_struc_id(typename))
        if not struc:
            continue
        struc.ordinal = -1
        idaapi.save_struc(struc, False)
        
def get_type_by_name(name):
    ti = idaapi.get_idati()
    type_ord = idaapi.get_type_ordinal(ti, name)
    # typ_type, typ_fields, typ_cmt, typ_fieldcmts, typ_sclass
    return ida_typeinf.get_numbered_type(ti, type_ord)
        
def set_function_signature(ea, typedef):
    idaapi.apply_type(ea, ida_typeinf.parse_decl(typedef, ida_typeinf.PT_SIL), idaapi.TINFO_DEFINITE)
        
def import_primitives():
    type_map = {
    "BUILTIN_STRING": "string",
    "uint8_t": "uint8",
    "uint16_t": "uint16",
    "uint32_t": "uint32",
    "uint64_t": "uint64",
    "int8_t": "int8",
    "int16_t": "int16",
    "int32_t": "int32",
    "double": "float64",
    "float": "float32",
    "complex64_t": "complex64",
    "complex128_t": "complex128",
    "void*": "uintptr", # should be uint64 or uint32 depending on ptr size, but this works too
    "uint8": "byte",
    "int32": "rune",
    "int": "void*" # int in GO depends on architecture size
    }
    
    ida_typeinf.idc_parse_types("struct BUILTIN_INTERFACE{void *tab;void *data;};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
    ida_typeinf.idc_parse_types("struct BUILTIN_STRING{char *ptr;size_t len;};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
    
    ida_typeinf.idc_parse_types("struct complex64_t{float real;float imag;};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
    ida_typeinf.idc_parse_types("struct complex128_t{double real;double imag;};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
    
    for ida_type, gotype in type_map.items():
        ida_typeinf.idc_parse_types(f"typedef {ida_type} {gotype};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
       
def forward_declare_structs(types):
    for typ in types:
        if typ['Kind'] == 'Struct':
            ida_typeinf.idc_parse_types(f"struct {typ['CStr']};", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
       
hints = ida_kernwin.ask_file(0, "*.*", "GoReSym output file")
with open(hints, "r", encoding="utf-8") as rp:
    buf = rp.read()

hints = json.loads(buf)
if iterable(hints['UserFunctions']):
    for func in hints['UserFunctions']:
        ida_bytes.del_items(func['Start'])
        ida_funcs.add_func(func['Start'])
        print("Renaming %s to %s" % (hex(func['Start']), func['FullName']))
        idaapi.add_func(func['Start'], func['End'])
        idaapi.set_name(func['Start'], func['FullName'], idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)

if iterable(hints['StdFunctions']):
    for func in hints['StdFunctions']:
        print("Renaming %s to %s" % (hex(func['Start']), func['FullName']))
        ida_bytes.del_items(func['Start'])
        ida_funcs.add_func(func['Start'])
        idaapi.add_func(func['Start'], func['End'])
        idaapi.set_name(func['Start'], func['FullName'], idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)

if iterable(hints['Types']):
    import_primitives()
    
    # we must do this to prevent IDA from creating an invalid struct of type int when we import things like typedef <class>* <newname>.
    # it would have made typedef struct <class> int; without a forward declaration. That would then break importing the class later with redefinition error.
    forward_declare_structs(hints['Types'])
    
    for typ in hints['Types'][::-1]:
        if typ.get('CReconstructed'):
            errors = ida_typeinf.idc_parse_types(typ['CReconstructed'] + ";", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
            if errors > 0:
                print(typ['CReconstructed'], "failed to import")
        
    # just for precation
    resync_local_types()
                
    for typ in hints['Types']:
        print("Renaming %s to %s" % (hex(typ['VA']), typ['Str']))
        idaapi.set_name(typ['VA'], typ['Str'], idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)
        
        # IDA often thinks these are string pointers, lets undefine that, then set the type correctly
        ida_bytes.del_items(typ['VA'], 0, 4)
        abi_typ, abi_typ_fields, _, _, _ = get_type_by_name("abi_Type")
        idaapi.apply_type(idaapi.get_idati(), abi_typ, abi_typ_fields, typ['VA'], idaapi.TINFO_DEFINITE)

if iterable(hints['Interfaces']):
    for typ in hints['Interfaces']:
        print("Renaming %s to %s" % (hex(typ['VA']), typ['Str']))
        idaapi.set_name(typ['VA'], typ['Str'], idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)
        
        # IDA often thinks these are string pointers, lets undefine that, then set the type correctly
        ida_bytes.del_items(typ['VA'], 0, 4)
        abi_typ, abi_typ_fields, _, _, _ = get_type_by_name("abi_Type")
        idaapi.apply_type(idaapi.get_idati(), abi_typ, abi_typ_fields, typ['VA'], idaapi.TINFO_DEFINITE)

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
