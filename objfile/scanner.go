package objfile

import (
	"encoding/binary"

	"github.com/hillu/go-yara/v4"
)

type signatureModuleDataInitx64 struct {
	moduleDataPtrLoc       uint8 // offset in signature to the location of the pointer to the PCHeader
	moduleDataPtrOffsetLoc uint8 // Ptr is a relative ptr, we need to include the instruction length + next instruction IP to resolve final VA
	signature              string
	namespace              string
}

type signatureModuleDataInitx86 struct {
	moduleDataPtrLoc uint8 // offset in signature to the location of the pointer to the PCHeader (ptr is absolute addr)
	signature        string
	namespace        string
}

type signatureModuleDataInitPPC struct {
	moduleDataPtrHi uint8
	moduleDataPtrLo uint8
	signature       string
	namespace       string
}

type SignatureMatch struct {
	moduleDataVA uint64
}

// 0x000000000044D80A: 48 8D 0D 8F DA 26 00                    lea     rcx, runtime_firstmoduledata
// 0x000000000044D811: EB 0D                                   jmp     short loc_44D820
// 0x000000000044D813: 48 8B 89 30 02 00 00                    mov     rcx, [rcx+230h]
// 0x000000000044D81A: 66 0F 1F 44 00 00                       nop     word ptr [rax+rax+00h]    <- always seems to be present
var x64sig = signatureModuleDataInitx64{3, 7, `rule x64firstmoduledata
{
    strings:
        $sig = { 48 8D 0? ?? ?? ?? ?? EB ?? 48 8? 8? ?? 02 00 00 66 0F 1F 44 00 00 }
    condition:
        $sig
}`, "x64"}

// 0x00438A94: 8D 05 60 49 6A 00                       lea     eax, off_6A4960
// 0x00438A9A: EB 1A                                   jmp     short loc_438AB6
// ...gap...
// 0x00438AAC: 8B 80 18 01 00 00                       mov     eax, [eax+118h]
// 0x00438AB2: 8B 54 24 20                             mov     edx, [esp+2Ch+var_C]
// 0x00438AB6:
// 0x00438AB6:                         loc_438AB6:                             ; CODE XREF: sub_438A60+3A↑j
// 0x00438AB6: 85 C0                                   test    eax, eax
// 0x00438AB8: 75 E2                                   jnz     short loc_438A9C
var x86sig = signatureModuleDataInitx86{2, `rule x86firstmoduledata
{
    strings:
        $sig = { 8D ?? ?? ?? ?? ?? EB ?? [8-50] 8B ?? ?? 01 00 00 8B ?? ?? ?? 85 ?? 75 ??}
    condition:
        $sig
}`, "x86"}

// 0x0000000000061a74:  3C 80 00 2C    lis  r4, 0x2c       // moduledata
// 0x0000000000061a78:  38 84 80 00    addi r4, r4, 0x8000  // moduledata ((0x2c << 16) - 0x8000)
// 0x0000000000061a7c:  48 00 00 08    b    0x61a84
// 0x0000000000061a80:  E8 84 02 30    ld   r4, 0x230(r4)
// 0x0000000000061a84:  7C 24 00 00    cmpd r4, r0
// 0x0000000000061a88:  41 82 01 A8    beq  0x61c30
var PPC_BE_sig = signatureModuleDataInitPPC{2, 6, `rule PPC_BEfirstmoduledata
{
    strings:
        $sig = { 3? 80 00 ?? 3? ?? ?? ?? 48 ?? ?? ?? E? ?? 02 ?? 7C ?? ?? ?? 41 82 ?? ??}
    condition:
        $sig
}`, "PPC_BE"}

// 0x000000000005C1E8 41 14 00 F0        ADRP            X1, #unk_2E7000    // 0xF0001441 -> 0b1 11 10000 0000000000010100010 00001 -> op=1, immlo=0b11, immhi=0b0000000000010100010
// ........................................................................ // X1 = ((0b0000000000010100010 11 << 12) + 0x5C1E8) = 0b1011100111000111101000 = 0b1011100111000111101000 & 0xFFFFFFFFFFFFF000 = 0x2E7000
// 0x000000000005C1EC 21 80 3D 91        ADD             X1, X1, #firstmoduleData@PAGEOFF // 0x913d8021 -> 0b100 100010 0 111101100000 00001 00001 -> sh = 0, imm12 = 0b111101100000, Rn = 00001, Rb = 00001
// ....................................................................... // X1 = 0x2E7000 + 0b111101100000 (0xF60) = 0x2E7F60
// 0x000000000005C1F0 02 00 00 14        B               loc_5C1F8     0x14 00 00 02
// 0x000000000005C1F4 21 18 41 F9        LDR             X1, [X1,#0x230]
// 0x000000000005C1F8 21 0D 00 B4        CBZ             X1, loc_5C39C   0xb4000d21
// var ARM64_sig = ?? ?? ?? (90 | b0 | f0 | d0) ?? ?? ?? 91 ?? ?? ?? (14 | 17) ?? ?? 41 F9 ?? ?? ?? B4

func findModuleInitPCHeader(data []byte, sectionBase uint64) []SignatureMatch {
	var matches []SignatureMatch = make([]SignatureMatch, 0)

	c, _ := yara.NewCompiler()
	c.AddString(x64sig.signature, x64sig.namespace)
	c.AddString(x86sig.signature, x86sig.namespace)
	c.AddString(PPC_BE_sig.signature, PPC_BE_sig.namespace)
	rules, err := c.GetRules()
	if err != nil {
		return matches
	}

	var yara_matches yara.MatchRules
	scanner, err := yara.NewScanner(rules)
	if err != nil {
		return matches
	}
	scanner.SetCallback(&yara_matches)

	scanner.ScanMem(data)
	for _, match := range yara_matches {
		for _, match_str := range match.Strings {
			sigPtr := match_str.Offset
			if match.Namespace == x64sig.namespace {
				// this is the pointer offset stored in the instruction
				// 0x44E06A:       48 8D 0D 4F F0 24 00 lea     rcx, off_69D0C0 (result: 0x24f04f)
				moduleDataPtrOffset := uint64(binary.LittleEndian.Uint32(data[sigPtr+uint64(x64sig.moduleDataPtrLoc):][:4]))

				// the ptr we get is position dependant, add the sigPtr + sectionBase to get current IP, then offset to next instruction
				// as relative ptrs are encoded by the NEXT instruction va, not the current one
				moduleDataIpOffset := sigPtr + sectionBase + uint64(x64sig.moduleDataPtrOffsetLoc)
				matches = append(matches, SignatureMatch{
					moduleDataPtrOffset + moduleDataIpOffset,
				})
			} else if match.Namespace == x86sig.namespace {
				moduleDataPtr := uint64(binary.LittleEndian.Uint32(data[sigPtr+uint64(x86sig.moduleDataPtrLoc):][:4]))
				matches = append(matches, SignatureMatch{
					moduleDataPtr,
				})
			} else if match.Namespace == PPC_BE_sig.namespace {
				moduleDataPtrHi := int64(binary.BigEndian.Uint16(data[sigPtr+uint64(PPC_BE_sig.moduleDataPtrHi):][:2]))

				// addi takes a signed immediate
				moduleDataPtrLo := int64(int16(binary.BigEndian.Uint16(data[sigPtr+uint64(PPC_BE_sig.moduleDataPtrLo):][:2])))

				moduleDataIpOffset := uint64((moduleDataPtrHi << 16) + moduleDataPtrLo)
				matches = append(matches, SignatureMatch{
					moduleDataIpOffset,
				})
			}
		}
	}

	return matches
}
