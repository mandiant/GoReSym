package objfile

import (
	"encoding/binary"
)

type signatureModuleDataInit struct {
	moduleDataPtrLoc       uint8  // offset in signature to the location of the pointer to the PCHeader
	moduleDataPtrOffsetLoc int    // Ptr is a relative ptr, we need to include the instruction length + next instruction IP to resolve final VA
	signature              []byte // signature to search for (0x90 is wildcard)
}

type SignatureMatch struct {
	moduleDataRVA uint64 // caller is responsible for adding the section base to this RVA
}

// TODO: Support more architectures in this mode - will involve big endian support for at least ppc64 (just one pointer read in the scanner here)
var x64sig = []signatureModuleDataInit{
	{21, 25, []byte("\x48\x8D\x05\x90\x90\x90\x90\x90\xE8\x90\x90\x90\x90\x48\x89\x44\x24\x90\x48\x8D\x0D\x90\x90\x90\x90\xEB\x0D")},
}

func findModuleInitPCHeader(data []byte) *SignatureMatch {
	var sigs []signatureModuleDataInit = x64sig

	for _, sigMeta := range sigs {
		var sigIdx = 0
		var isMatch = false
		var sigPtr = uint64(0)
		for idx := range data {
			if len(data[idx:]) < len(sigMeta.signature)-sigIdx {
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
				sigPtr = uint64(idx)
				isMatch = true
			}

			if sigIdx == len(sigMeta.signature)-1 {
				// this is the pointer offset stored in the instruction
				// 0x44E06A:       48 8D 0D 4F F0 24 00 lea     rcx, off_69D0C0 (result: 0x24f04f)
				moduleDataPtrOffset := uint64(binary.LittleEndian.Uint32(data[sigPtr+uint64(sigMeta.moduleDataPtrLoc):][:4]))

				// typically you'd now do 0x44E06A + 7 = nextInstruction then nextInstruction + 0x24f04f = final VA. But we don't know the section base yet.
				// Taking our equation nextInstruction + 0x24f04f = final VA, we can rewrite: (sectionBase + offsetNextInstruction) + 0x24f04f = final VA
				// offsetNextInstruction is the same as our sigPtr + some X which we know based on the signature we wrote.
				// We therefore finally do moduleDataIpOffset = sigPtr + PCHeaderPtrOffset, sectionBase + moduleDataIpOffset + 0x24f04f = final VA
				// and that gives us an RVA relative to the sectionBase, which we just add back in whatever calls this function
				// it's actually simple, just confusing :)
				moduleDataIpOffset := uint64(sigPtr) + uint64(sigMeta.moduleDataPtrOffsetLoc)
				return &SignatureMatch{
					moduleDataPtrOffset + moduleDataIpOffset,
				}
			}
		}
	}

	return nil
}
