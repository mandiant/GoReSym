package objfile

import (
	"encoding/binary"
)

type signatureModuleDataInitx86_x64 struct {
	moduleDataPtrLoc       uint8  // offset in signature to the location of the pointer to the PCHeader
	moduleDataPtrOffsetLoc uint8  // Ptr is a relative ptr, we need to include the instruction length + next instruction IP to resolve final VA
	signature              []byte // signature to search for (0x90 is wildcard)
}

type signatureModuleDataInitPPC struct {
	moduleDataPtrHi uint8
	moduleDataPtrLo uint8
	signature       []byte // signature to search for (0x90 is wildcard)
}

type SignatureMatch struct {
	moduleDataVA uint64
}

// TODO: Support more architectures in this mode - will involve big endian support for at least ppc64 (just one pointer read in the scanner here)
var x64sig = signatureModuleDataInitx86_x64{21, 25, []byte("\x48\x8D\x05\x90\x90\x90\x90\x90\xE8\x90\x90\x90\x90\x48\x89\x44\x24\x90\x48\x8D\x0D\x90\x90\x90\x90\xEB\x0D")}

// 0x0000000000061a74:  3C 80 00 2C    lis  r4, 0x2c       // moduledata
// 0x0000000000061a78:  38 84 80 00    addi r4, r4, 0x8000  // moduledata ((0x2c << 16) + 0x8000)
// 0x0000000000061a7c:  48 00 00 08    b    0x61a84
// 0x0000000000061a80:  E8 84 02 30    ld   r4, 0x230(r4)
// 0x0000000000061a84:  7C 24 00 00    cmpd r4, r0
// 0x0000000000061a88:  41 82 01 A8    beq  0x61c30
var PPC_BE_sig = signatureModuleDataInitPPC{2, 6, []byte("\x90\x80\x00\x2C\x90\x90\x80\x00\x48\x90\x90\x08\x90\x90\x02\x30\x7C\x90\x00\x00\x41\x82\x90\x90")}

func findPattern(data []byte, signature []byte, callback func(uint64) []SignatureMatch) []SignatureMatch {
	var matches []SignatureMatch = make([]SignatureMatch, 0)
	var sigIdx = uint64(0)

	for idx := range data {
		if uint64(len(data[idx:])) < uint64(len(signature))-sigIdx {
			break
		}

		if signature[sigIdx] == 0x90 {
			// nop instruction is considered "wildcard"
			sigIdx += 1
		} else if signature[sigIdx] == data[idx] {
			// Byte in signature is equal to position in data
			sigIdx += 1
		} else {
			sigIdx = 0
			continue
		}

		if sigIdx == uint64(len(signature))-1 {
			matches = append(matches, callback(uint64(idx-len(signature)+2))...)
			sigIdx = 0 // reset, scan rest of data for other matches
		}
	}
	return matches
}

func findModuleInitPCHeader(data []byte, sectionBase uint64, imageBase uint64) []SignatureMatch {
	var matches []SignatureMatch = make([]SignatureMatch, 0)

	// x64 scan
	matches = append(matches, findPattern(data, x64sig.signature, func(sigPtr uint64) []SignatureMatch {
		// this is the pointer offset stored in the instruction
		// 0x44E06A:       48 8D 0D 4F F0 24 00 lea     rcx, off_69D0C0 (result: 0x24f04f)
		moduleDataPtrOffset := uint64(binary.LittleEndian.Uint32(data[sigPtr+uint64(x64sig.moduleDataPtrLoc):][:4]))

		// typically you'd now do 0x44E06A + 7 = nextInstruction then nextInstruction + 0x24f04f = final VA. But we don't know the section base yet.
		// Taking our equation nextInstruction + 0x24f04f = final VA, we can rewrite: (sectionBase + offsetNextInstruction) + 0x24f04f = final VA
		// offsetNextInstruction is the same as our sigPtr + some X which we know based on the signature we wrote.
		// We therefore finally do moduleDataIpOffset = sigPtr + PCHeaderPtrOffset, sectionBase + moduleDataIpOffset + 0x24f04f = final VA
		// and that gives us an RVA relative to the sectionBase, which we just add back in whatever calls this function
		// it's actually simple, just confusing :)
		moduleDataIpOffset := uint64(sigPtr) + uint64(x64sig.moduleDataPtrOffsetLoc)
		return []SignatureMatch{{
			moduleDataPtrOffset + moduleDataIpOffset + sectionBase,
		}}
	})...)

	// PPC BE scan
	matches = append(matches, findPattern(data, PPC_BE_sig.signature, func(sigPtr uint64) []SignatureMatch {
		moduleDataPtrHi := uint64(binary.BigEndian.Uint16(data[sigPtr+uint64(PPC_BE_sig.moduleDataPtrHi):][:2]))
		moduleDataPtrLo := uint64(binary.BigEndian.Uint16(data[sigPtr+uint64(PPC_BE_sig.moduleDataPtrLo):][:2]))

		moduleDataIpOffset := (moduleDataPtrHi << 16) + moduleDataPtrLo
		return []SignatureMatch{{
			moduleDataIpOffset - imageBase,
		}}
	})...)

	return matches
}
