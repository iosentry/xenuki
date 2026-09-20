# XenUKI

A Rust tool that packs the Xen hypervisor, a Linux Dom0 kernel, and their
initramfs images into a single Unified Kernel Image (UKI) — a monolithic
PE32+ EFI executable that UEFI Secure Boot can verify directly.

## The problem

Xen doesn't boot like a normal Secure Boot–compliant kernel. It loads via
multiboot2, with the hypervisor, Dom0 kernel, and ramdisk as separate
files, glued together by a bootloader (GRUB, or a similar multiboot2-aware
loader). To get that chain under Secure Boot, you end up trusting the
bootloader itself as a stand-in for the hypervisor — signing GRUB, not Xen.
That's an extra link in the trust chain that doesn't need to exist, and it
means the actual privileged code (Xen) is never the thing UEFI is directly
attesting.

UKIs solve this for regular Linux systems by bundling kernel + initramfs +
cmdline into one signed PE binary that UEFI boots straight from the EFI
System Partition, no bootloader required. Xen doesn't fit that model
out of the box, because it isn't a single Linux kernel image — it's a
hypervisor plus a Dom0 kernel plus a ramdisk.

## What XenUKI does

XenUKI builds the same kind of single, signable EFI binary, but for the
Xen + Dom0 pair:

- Combines the Xen hypervisor, Dom0 kernel, and initramfs into one image
- Produces a PE32+ EFI executable that's Secure Boot compliant
- Removes the bootloader as a separate trust anchor — UEFI verifies the
  signature on the actual hypervisor/kernel bundle, not an intermediary

## Status

Early stage. Current work is split between validating packer output
against the UKI spec, and building out a VM-based test methodology for
boot-level validation (Secure Boot verification and TPM measurements).

