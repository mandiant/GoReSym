# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
import idaapi
import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_typeinf
import ida_auto
import idautils
import idc
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
    t = idaapi.tinfo_t()
    t.get_named_type(None, name)
    return t
        
def set_function_signature(ea, typedef):
    idc.apply_type(ea, idc.parse_decl(typedef, ida_typeinf.PT_SIL), idaapi.TINFO_DEFINITE)
        
# special types needed for other imports that we can't necessary expect to be recovered from the pclntab symbols
def import_special_types():
    ida_special_types = [
        "typedef uint8 _32_uint8[32]",
        "typedef _32_uint8* _ptr_32_uint8",
        "typedef int32 _32_int32[32]",
        "typedef _32_int32* _ptr_32_int32",
        "typedef uint8 _4_uint8[4]",
        "typedef _4_uint8* _ptr_4_uint8",
        "struct _slice_unsafe_Pointer{unsafe_Pointer *ptr;size_t len;size_t cap;}",
        "struct abi_MapType{abi_Type Type;abi_Type* Key;abi_Type* Elem;abi_Type* Bucket;void* hasherFn;uint8 KeySize;uint8 ValueSize;uint16 BucketSize;uint32 Flags;}",
        "typedef abi_MapType* _ptr_abi_MapType",
        "struct runtime_hiter {unsafe_Pointer key;unsafe_Pointer elem;unsafe_Pointer t;unsafe_Pointer h;unsafe_Pointer buckets;unsafe_Pointer bptr;_slice_unsafe_Pointer* overflow;_slice_unsafe_Pointer* oldoverflow;uintptr startBucket;uint8 offset;bool wrapped;uint8 B;uint8 i;uintptr bucket;uintptr checkBucket;}",
        "typedef runtime_hiter* _ptr_runtime_hiter",
    ]
    
    for special in ida_special_types:
        ida_typeinf.idc_parse_types(special + ";", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
        
def import_primitives():
    type_map = {
        "BUILTIN_STRING": "string",
        "uint8_t": "uint8",
        "uint16_t": "uint16",
        "uint32_t": "uint32",
        "uint64_t": "uint64",
        #"int": "void*", # int in GO depends on architecture size
        "int8_t": "int8",
        "int16_t": "int16",
        "int32_t": "int32",
        "int64_t": "int64",
        "double": "float64",
        "float": "float32",
        "complex64_t": "complex64",
        "complex128_t": "complex128",
        "void*": "uintptr", # should be uint64 or uint32 depending on ptr size, but this works too
        "uint8": "byte",
        "int32": "rune",
        "BUILTIN_INTERFACE": "any", # any aliases interface
        "BUILTIN_INTERFACE": "Interface", # Interface in source aliases IDAs builtin
        "void*": "unsafe_Pointer",
    }
    
    # special types needed for other imports that we can't necessary expect to be recovered from the pclntab symbols
    
    
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

def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))
       
# Controls if __golang is reg or stack abi
def set_ida_golang_abi(reg_abi_on):
    # alternative ida_loader.load_and_run_plugin("golang", 118)
    # value = node.supval(0, 'A')
    
    node = idaapi.netnode("$ golang", 0, True)
    if reg_abi_on:
        REG_ABI_ON = 118
        node.supset(0, REG_ABI_ON.to_bytes(8, byteorder = 'little'), 'A')
    else:
        REG_ABI_OFF = 0
        node.supset(0, REG_ABI_OFF.to_bytes(8, byteorder = 'little'), 'A')

runtime_fn_typedefs = {}
def load_runtime_defs(go_version):
    version_parts = go_version.split(".")
    major_version = version_parts[0] + '.' + version_parts[1] # 1.21.2 -> 1.21
    minor_version = version_parts[1]
    
    if version_parts[0] == "1" and int(minor_version) >= 17:
        set_ida_golang_abi(True)
    else:
        set_ida_golang_abi(False)
    
    with open(f"{get_script_path()}/RuntimeDefinitions/go{major_version}.json", "r", encoding="utf-8") as rp:
        buf = rp.read()
    runtime_defs = json.loads(buf)
    for function_name in runtime_defs:
        ret_typ = runtime_defs[function_name]['result']
        ret_typ_name = runtime_defs[function_name]['result_name']
        param_typs = runtime_defs[function_name]['parameters']
        
        ret_typ_ida_str = None
        if ret_typ_name: # this is a multi-value return type, import the structure we represent this with
            status = ida_typeinf.idc_parse_types(ret_typ + ";", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
            ret_typ_ida_str = ret_typ_name
            print("Imported: " + ret_typ_name + " " + str(status))
        else:
            ret_typ_ida_str = ret_typ # simple type, already imported
            
        c_fn_typdef = f"{ret_typ_ida_str} __golang {function_name}("
        for i, param in enumerate(param_typs):
            param_name = param['name']
            param_type = param['type']
            c_fn_typdef += f"{param_type} {param_name}"
            if i != len(param_typs) - 1:
                c_fn_typdef += ", "
        c_fn_typdef += ")"
        runtime_fn_typedefs[function_name] = c_fn_typdef
 
hints = ida_kernwin.ask_file(0, "*.*", "GoReSym output file")
with open(hints, "r", encoding="utf-8") as rp:
    buf = rp.read()
 
hints = json.loads(buf)
import_primitives()

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
    # we must do this to prevent IDA from creating an invalid struct of type int when we import things like typedef <class>* <newname>.
    # it would have made typedef struct <class> int; without a forward declaration. That would then break importing the class later with redefinition error.
    forward_declare_structs(hints['Types'])
    
    for typ in hints['Types'][::-1]:
        if typ.get('CReconstructed'):
            errors = ida_typeinf.idc_parse_types(typ['CReconstructed'] + ";", ida_typeinf.HTI_PAKDEF | ida_typeinf.HTI_DCL)
            if errors > 0:
                print(typ['CReconstructed'], "failed to import")
        
    resync_local_types()
                
    for typ in hints['Types']:
        print("Renaming %s to %s" % (hex(typ['VA']), typ['Str']))
        idaapi.set_name(typ['VA'], typ['Str'], idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)
        
        # IDA often thinks these are string pointers, lets undefine that, then set the type correctly
        ida_bytes.del_items(typ['VA'], 0, 4)
        abi_typ = get_type_by_name("abi_Type")
        idaapi.apply_tinfo(typ['VA'], abi_typ, idaapi.TINFO_DEFINITE)

if iterable(hints['Interfaces']):
    for typ in hints['Interfaces']:
        print("Renaming %s to %s" % (hex(typ['VA']), typ['Str']))
        idaapi.set_name(typ['VA'], typ['Str'], idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)
        
        # IDA often thinks these are string pointers, lets undefine that, then set the type correctly
        ida_bytes.del_items(typ['VA'], 0, 4)
        abi_typ = get_type_by_name("abi_Type")
        idaapi.apply_tinfo(typ['VA'], abi_typ, idaapi.TINFO_DEFINITE)

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

# it seems to be necessary to wait before applying types
print("Waiting for auto-analysis to complete...")
ida_auto.auto_wait()
print("Complete! Applying function typedefs...")

import_special_types()
load_runtime_defs(hints['Version'])
resync_local_types()

for func_ea in idautils.Functions():
    func_name = ida_funcs.get_func_name(func_ea)
    print(func_name)
            
    c_fn_typdef = runtime_fn_typedefs.get(func_name.replace('.', '_'))
    if c_fn_typdef:
        print("TYPEDEF: " + hex(func_ea) + " " + c_fn_typdef)
        set_function_signature(func_ea, c_fn_typdef)
        
resync_local_types()