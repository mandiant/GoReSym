
package objfile

import (
	"encoding/binary"
)

type signatureMetaData struct {
	PCHeaderPtrLoc		int        // offset in signature to the location of the pointer to the PCHeader
	targetInstIdx		int        // offset in signature to the instruction after the PCHeader pointer
	signature			[]byte     // signature to search for (0x90 is wildcard)
}

var peSigs = []signatureMetaData {
	{21, 25, []byte("\x48\x8D\x05\x90\x90\x90\x90\x90\xE8\x90\x90\x90\x90\x48\x89\x44\x24\x90\x48\x8D\x0D\x90\x90\x90\x90\xEB\x0D")},
}

var elfSigs = []signatureMetaData {
	{21, 25, []byte("\x48\x8D\x05\x90\x90\x90\x90\x90\xE8\x90\x90\x90\x90\x48\x89\x44\x24\x90\x48\x8D\x0D\x90\x90\x90\x90\xEB\x0D")},
}

var machoSigs = []signatureMetaData {
	{21, 25, []byte("\x48\x8D\x05\x90\x90\x90\x90\x90\xE8\x90\x90\x90\x90\x48\x89\x44\x24\x90\x48\x8D\x0D\x90\x90\x90\x90\xEB\x0D")},
}


const (
	peScanner	    uint32 = 0x1
	elfScanner 	    uint32 = 0x2
	machoScanner	uint32 = 0x3
)

func findModuleInitPCHeader(os uint32, data []byte) []uint64 {
	var sigs []signatureMetaData
	switch os {
	case 1:
		sigs = peSigs
	case 2:
		sigs = elfSigs
	case 3:
		sigs = machoSigs
	}

	for _, sigMeta := range sigs {
		var sigIdx = 0
		var isMatch = false
		var sigPtr = 0
		for idx := range data {
			if len(data[idx:]) < len(sigMeta.signature) - sigIdx {
				break
			}

			if sigMeta.signature[sigIdx] == 0x90 {
				// nop instruction is considered "wildcard"
				sigIdx += 1
			} else if sigMeta.signature[sigIdx] == data[idx] {
				// Byte in signature is equal to position in data
				sigIdx += 1
			} else {
				// No match
				isMatch = false
				sigIdx = 0
				continue
			}

			// store start index for signature attempt when it is a good signature 
			if !isMatch {
				sigPtr = idx
				isMatch = true
			}

			if sigIdx == len(sigMeta.signature)-1 {
				// found a match, return on first match
                moduleData := binary.LittleEndian.Uint32(data[sigPtr+sigMeta.PCHeaderPtrLoc:][:4])
				return []uint64{uint64(moduleData), uint64(sigPtr)+uint64(sigMeta.targetInstIdx)}
			}
		}
	}

	return []uint64{}

}
