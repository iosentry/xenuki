#!/usr/bin/env python3
"""Filter a concatenated Intel microcode file (e.g. GenuineIntel.bin from
intel-ucode.img) down to client (desktop/laptop) CPUs from Skylake onward.

usage: ucode-filter.py <in GenuineIntel.bin> <out ucode.bin>

Blobs are matched on the CPUID family/model in their header, so every
stepping/platform variant of a kept model stays. Server/HEDT models (Xeon SP,
Atom server, Xeon Phi) and everything before Skylake are dropped.
"""
import struct
import sys

# family 6 model -> name. Linux arch/x86/include/asm/intel-family.h naming.
KEEP = {
    0x4E: "Skylake-U/Y", 0x5E: "Skylake-S/H",
    0x8E: "Kaby/Amber/Whiskey/Comet Lake-U/Y", 0x9E: "Kaby/Coffee Lake-S/H",
    0xA5: "Comet Lake-S/H", 0xA6: "Comet Lake-U",
    0x66: "Cannon Lake-U", 0x7D: "Ice Lake", 0x7E: "Ice Lake-U/Y",
    0x8C: "Tiger Lake-U", 0x8D: "Tiger Lake-H", 0xA7: "Rocket Lake",
    0x8A: "Lakefield",
    0x97: "Alder Lake-S", 0x9A: "Alder Lake-P", 0xBE: "Alder Lake-N",
    0xB7: "Raptor Lake-S", 0xBA: "Raptor Lake-P", 0xBF: "Raptor Lake-S",
    0xAA: "Meteor Lake", 0xAC: "Meteor Lake",
    0xC5: "Arrow Lake-H", 0xC6: "Arrow Lake-S", 0xB5: "Arrow Lake-U",
    0xBD: "Lunar Lake", 0xCC: "Panther Lake", 0xD5: "Wildcat Lake",
    # client Atom (Celeron/Pentium Silver laptops and desktops)
    0x5C: "Apollo Lake", 0x7A: "Gemini Lake", 0x9C: "Jasper Lake",
}


def blobs(data):
    off = 0
    while off < len(data):
        if len(data) - off < 48:
            sys.exit(f"truncated header at {off:#x}")
        hdrver, _rev, _date, sig, _ck, ldrver, _pf, _dsz, totsz = \
            struct.unpack_from("<9I", data, off)
        total = totsz or 2048
        if hdrver != 1 or ldrver != 1 or total % 4 or off + total > len(data):
            sys.exit(f"bad microcode header at {off:#x}")
        blob = data[off:off + total]
        if sum(struct.unpack(f"<{total // 4}I", blob)) & 0xFFFFFFFF:
            sys.exit(f"checksum error at {off:#x}")
        yield sig, blob
        off += total


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    data = open(sys.argv[1], "rb").read()
    out, kept, dropped = bytearray(), {}, 0
    for sig, blob in blobs(data):
        family = (sig >> 8) & 0xF
        model = ((sig >> 4) & 0xF) | ((sig >> 12) & 0xF0)
        if family == 6 and model in KEEP:
            out += blob
            kept[model] = kept.get(model, 0) + 1
        else:
            dropped += 1
    open(sys.argv[2], "wb").write(out)
    for model in sorted(kept):
        print(f"  6/{model:02x} {KEEP[model]:<36} {kept[model]} blob(s)")
    print(f"kept {sum(kept.values())}, dropped {dropped}: "
          f"{len(data)} -> {len(out)} bytes")


if __name__ == "__main__":
    main()
