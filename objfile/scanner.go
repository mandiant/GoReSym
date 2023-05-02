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
var x64sig = signatureModuleDataInitx86_x64{21, 25, []byte("48 8D 05 ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 89 44 24 ?? 48 8D 0D ?? ?? ?? ?? EB 0D")}

// 0x0000000000061a74:  3C 80 00 2C    lis  r4, 0x2c       // moduledata
// 0x0000000000061a78:  38 84 80 00    addi r4, r4, 0x8000  // moduledata ((0x2c << 16) + 0x8000)
// 0x0000000000061a7c:  48 00 00 08    b    0x61a84
// 0x0000000000061a80:  E8 84 02 30    ld   r4, 0x230(r4)
// 0x0000000000061a84:  7C 24 00 00    cmpd r4, r0
// 0x0000000000061a88:  41 82 01 A8    beq  0x61c30
var PPC_BE_sig = signatureModuleDataInitPPC{2, 6, []byte("3? 80 00 2C 3? ?? 80 00 48 ?? ?? 08 E? ?? 02 30 7C ?? 00 00 41 82 ?? ??")}

func getPatternSize(signature []byte) int {
	// c = 2 * b + (b - 1) . 2 chars per byte + b - 1 spaces between
	return (len(signature) + 1) / 3
}

func getBits(x byte) byte {
	if x >= '0' && x <= '9' {
		return x - '0'
	} else {
		return (x & 0xDF) - 'A' + 0xa
	}
}

// Pattern must have a space per byte, use ? as wildcard for nibbles, and be uppercase ascii text without the 0x or /x prefix
func findPattern(data []byte, signature []byte, callback func(uint64) []SignatureMatch) []SignatureMatch {
	var matches []SignatureMatch = make([]SignatureMatch, 0)
	patternSize := getPatternSize(signature)
	for i := range data {
		sigIdx := 0
		for sigIdx < patternSize {
			sigPatIdx := sigIdx * 3
			sigHi := getBits(signature[sigPatIdx:][0]) << 4
			sigLo := getBits(signature[sigPatIdx:][1])
			datByt := data[i+sigIdx:][0]

			// check for ex: A?
			if signature[sigPatIdx+1] == '?' {
				sigLo = datByt & 0xF
			}

			if signature[sigPatIdx] == '?' {
				sigHi = datByt & 0xF0
			}

			if datByt != (sigHi | sigLo) {
				break
			}

			sigIdx += 1
		}

		if sigIdx >= patternSize {
			matches = append(matches, callback(uint64(i))...)
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
