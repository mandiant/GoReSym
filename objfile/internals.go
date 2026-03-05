/*Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.*/
package objfile

type pvoid64 uint64

// All types following this are the binary representation of internal objects.
// These are 'flat', i.e. one pointer level deep. Access to pointers and such
// require a memory read to retrieve the backing data.
// https://github.com/golang/go/blob/23adc139bf1c0c099dd075da076f5a1f3ac700d4/src/reflect/value.go#L2599
type GoSlice64 struct {
	Data     pvoid64
	Len      uint64
	Capacity uint64
}



type Textsect struct {
	Vaddr    uint64 // prelinked section vaddr
	End      uint64 // vaddr + section length
	Baseaddr uint64 // relocated section address
}



type Kind uint8 // mask & 0x1f

const (
	Invalid Kind = iota
	Bool
	Int
	Int8
	Int16
	Int32
	Int64
	Uint
	Uint8
	Uint16
	Uint32
	Uint64
	Uintptr
	Float32
	Float64
	Complex64
	Complex128
	Array
	Chan
	Func
	Interface
	Map
	Pointer
	Slice
	String
	Struct
	UnsafePointer
)

func (k Kind) String() string {
	switch k {
	case Bool:
		return "Bool"
	case Int:
		return "Int"
	case Int8:
		return "Int8"
	case Int16:
		return "Int16"
	case Int32:
		return "Int32"
	case Int64:
		return "Int64"
	case Uint:
		return "Uint"
	case Uint8:
		return "Uint8"
	case Uint16:
		return "Uint16"
	case Uint32:
		return "Uint32"
	case Uint64:
		return "Uint64"
	case Uintptr:
		return "Uintptr"
	case Float32:
		return "Float32"
	case Complex64:
		return "Complex64"
	case Complex128:
		return "Complex128"
	case Array:
		return "Array"
	case Chan:
		return "Chan"
	case Func:
		return "Func"
	case Interface:
		return "Interface"
	case Map:
		return "Map"
	case Pointer:
		return "Pointer"
	case Slice:
		return "Slice"
	case String:
		return "String"
	case Struct:
		return "Struct"
	case UnsafePointer:
		return "UnsafePointer"
	}
	return "Invalid"
}

type ChanDir uint

const (
	RecvOnly ChanDir               = 1 << iota // <-chan
	SendOnly                                   // chan<-
	SendRecv = RecvOnly | SendOnly             // chan
)

func (d ChanDir) String() string {
	switch d {
	case SendRecv:
		return "Both"
	case SendOnly:
		return "Send"
	case RecvOnly:
		return "Recv"
	}
	return "Invalid"
}

type tflag uint8
type nameOff int32
type typeOff int32



// This is a general structure that just holds the fields I care about
// this lets us return a single type, even though rtypes change between go version
type Type struct {
	VA             uint64
	Str            string
	CStr           string
	Kind           string
	Reconstructed  string `json:",omitempty"` // for Some types we can reconstruct the original definition back to Go code
	CReconstructed string `json:",omitempty"` // for Some types we can reconstruct the original definition back to C code

	// rtypes change between runtime versions. Depending on the 'Kind' additional data follows the 'base' rtype.
	// We store the size so that this base type can be skipped past, and the additional data read directly in a version independant way.
	baseSize uint16
	kindEnum Kind
	flags    tflag
}

// This is a general structure that just holds the fields I care about
// this lets us return a single type, even though moduledata changes between go version
type ModuleData struct {
	VA        uint64
	TextVA    uint64    // adjusted (ex: CGO) .text base that pclntab offsets are relative to
	Types     uint64    // points to type information
	ETypes    uint64    // points to end of type information
	Typelinks GoSlice64 // points to metadata about offsets into types for structures and other types
	ITablinks GoSlice64 // points to metadata about offsets into types for interfaces

	// Some versions of go with 1.2 moduledata use a slice instead of the types + offset typelinks list
	LegacyTypes GoSlice64
}

const (
	// tflagUncommon means that there is a pointer, *uncommonType,
	// just beyond the outer type structure.
	//
	// For example, if t.Kind() == Struct and t.tflag&tflagUncommon != 0,
	// then t has uncommonType data and it can be accessed as:
	//
	//	type tUncommon struct {
	//		structType
	//		u uncommonType
	//	}
	//	u := &(*tUncommon)(unsafe.Pointer(t)).u
	tflagUncommon tflag = 1 << 0

	// tflagExtraStar means the name in the str field has an
	// extraneous '*' prefix. This is because for most types T in
	// a program, the type *T also exists and reusing the str data
	// saves binary size.
	tflagExtraStar tflag = 1 << 1

	// tflagNamed means the type has a name.
	tflagNamed tflag = 1 << 2

	// tflagRegularMemory means that equal and hash functions can treat
	// this type as a single region of t.size bytes.
	tflagRegularMemory tflag = 1 << 3
)

// https://github.com/golang/go/blob/9ecb853cf2252f3cd9ed2e7b3401d17df2d1ab06/src/runtime/symtab.go#L662
func textAddr(off uint64, text uint64, textsectmap []Textsect) uint64 {
	res := text + off
	if len(textsectmap) > 1 {
		for i, sect := range textsectmap {
			// For the last section, include the end address (etext), as it is included in the functab.
			if off >= sect.Vaddr && off < sect.End || (i == len(textsectmap)-1 && off == sect.End) {
				res = sect.Baseaddr + off - sect.Vaddr
				break
			}
		}
	}
	return res
}

