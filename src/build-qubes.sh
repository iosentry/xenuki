#!/bin/bash
# Pack the Qubes Xen 4.19.5 + dom0 6.18.51 image from uki-build/build.tmp.
# usage: build-qubes.sh [path/to/xenuki]   (output: uki-build/qubes-uki/)
set -euo pipefail
cd "$(dirname "$0")/.."
XENUKI=${1:-xenuki}
B=build.tmp
O=qubes-uki
K=6.18.51-1.qubes.fc41.x86_64

# Microcode: raw GenuineIntel.bin from intel-ucode.img, client CPUs Skylake+ only.
if [ ! -f $O/GenuineIntel-all.bin ]; then
    T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
    (cd "$T" && cpio -id --quiet kernel/x86/microcode/GenuineIntel.bin) < $B/intel-ucode.img
    cp "$T/kernel/x86/microcode/GenuineIntel.bin" $O/GenuineIntel-all.bin
fi
python3 -I scripts/ucode-filter.py $O/GenuineIntel-all.bin $O/ucode.bin

# Ramdisk trimming:
#  - NVIDIA firmware + nouveau: the laptop panel is on the Intel iGPU; nouveau
#    loads after switch-root with firmware from the real root.
#  - kernel/x86/microcode + early_cpio marker: dracut's early-ucode cpio. Xen loads microcode from
#    .ucode and a PV dom0 never loads microcode itself.
"$XENUKI" \
    -e $B/xen-4.19.5.efi.stripped \
    -k $B/vmlinuz-$K \
    -r $B/initramfs-$K.img \
    -u $O/ucode.bin \
    -x $O/xen.cfg \
    --initrd-drop usr/lib/firmware/nvidia \
    --initrd-drop kernel/x86/microcode --initrd-drop early_cpio \
    --initrd-omit-module nouveau \
    --strip-symbols \
    -o $O/xen-4.19.5-qubes-6.18.51.efi
ls -l $O/xen-4.19.5-qubes-6.18.51.efi
