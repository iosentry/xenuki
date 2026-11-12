///                 This code generates a standalone monolithic bootable EFI executable
///                 file that enables the opportunity for SecureBoot enforcement on
///                 UEFI based systems that require heightened levels security vigilance.
///
///                 The binary file generated is a 64-bit PE32+ directly executable file
///                 conforming to Microsoft's Portable Executable (PE) file format. The
///                 hybrid Unified Kernel Image (UKI) generated provides a complete Xen
///                 Type-1 Hypervisor system as well as the administrative Domain0's Linux
///                 kernel, initramfs, cmdline, etc. needed to run a fully funtional Xen
///                 dom0. This architecture and design provides for the most effective use
///                 of SecureBoot integrity validation. Even the kernel's and hypervisor's
///                 initramfs contents are insured as they are packed directly into the binary.
///
///                 Output layout (file offsets, ascending, no gaps between sections so
///                 every Authenticode implementation hashes the same bytes):
///
///                   [ DOS hdr | PE hdr | optional hdr | section table ]  (SizeOfHeaders)
///                   [ original Xen section data, unchanged            ]
///                   [ .config | .kernel | .ramdisk | .ucode | .sbat | .osrel ]
///                   [ COFF symbol + string table (moved from the input; with
///                     --strip-symbols only the long section names remain) ]
///                   ( Authenticode certificate table is appended later by sbsign )
///
///                 Date: Fri Jul 24 08:01:10 AM CDT 2026
///                 Roman Hunt <roman@systemwarfare.net>
mod initrd;

use clap::Parser;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "xenuki", version, about)]
struct Args {
    /// Path to kernel img
    #[arg(short, long)]
    kernel: PathBuf,

    /// Path to ramdisk
    #[arg(short, long)]
    ramdisk: PathBuf,

    /// UKI output filename
    #[arg(short, long)]
    outfile: PathBuf,

    /// Path to xen.efi boot stub
    #[arg(short, long)]
    efistub: PathBuf,

    /// Path to the xen.cfg dom0 configuration file
    #[arg(short, long)]
    xencfg: PathBuf,

    /// Path to processor microcode img
    #[arg(short, long)]
    ucode: PathBuf,

    /// Optional SBAT CSV to embed as .sbat (required if the image is loaded through shim)
    #[arg(long)]
    sbat: Option<PathBuf>,

    /// Optional os-release file to embed as .osrel
    #[arg(long)]
    osrel: Option<PathBuf>,

    /// Drop a path (and everything below it) from the ramdisk before packing;
    /// `*` matches any characters. Repeatable.
    /// E.g. usr/lib/firmware/nvidia, kernel/x86/microcode
    #[arg(long, value_name = "PATH")]
    initrd_drop: Vec<String>,

    /// Remove a kernel module's .ko from the ramdisk and blacklist it inside
    /// the ramdisk only (it still loads after switch-root). Repeatable.
    #[arg(long, value_name = "MODULE")]
    initrd_omit_module: Vec<String>,

    /// Drop the efistub's COFF symbol table; only the string-table entries
    /// that hold long section names (e.g. ".data.read_mostly") are kept.
    #[arg(long)]
    strip_symbols: bool,
}

type Result<T> = std::result::Result<T, String>;

// ---------------------------------------------------------------------------
// Little-endian helpers with bounds checking (malformed input -> error, not panic)
// ---------------------------------------------------------------------------

fn rd_u16(data: &[u8], off: usize) -> Result<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| format!("read past end of file at {off:#x}"))
}

fn rd_u32(data: &[u8], off: usize) -> Result<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .ok_or_else(|| format!("read past end of file at {off:#x}"))
}

fn patch_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn patch_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

fn to_u32(value: u64, what: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| format!("{what} ({value:#x}) does not fit in 32 bits"))
}

fn pad_to(out: &mut Vec<u8>, len: usize) {
    if out.len() < len {
        out.resize(len, 0);
    }
}

// ---------------------------------------------------------------------------
// PE/COFF structures
// ---------------------------------------------------------------------------

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const PE32PLUS_MAGIC: u16 = 0x20b;

// Offsets inside the PE32+ optional header
const OPT_SIZE_OF_INITIALIZED_DATA: usize = 8;
const OPT_SECTION_ALIGNMENT: usize = 32;
const OPT_FILE_ALIGNMENT: usize = 36;
const OPT_SIZE_OF_IMAGE: usize = 56;
const OPT_SIZE_OF_HEADERS: usize = 60;
const OPT_CHECKSUM: usize = 64;
const OPT_NUMBER_OF_RVA_AND_SIZES: usize = 108;
const OPT_DATA_DIRECTORIES: usize = 112;

const DIR_SECURITY: usize = 4;
const DIR_DEBUG: usize = 6;

const SECTION_HEADER_SIZE: usize = 40;
const DEBUG_DIRECTORY_ENTRY_SIZE: usize = 28;

const IMAGE_SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;

#[derive(Debug)]
struct PeInfo {
    coff_base: usize, // offset of the COFF file header (just after "PE\0\0")
    opt_base: usize,  // offset of the optional header
    number_of_sections: u16,
    pointer_to_symbol_table: u32,
    sect_offset: usize, // offset of the section table
    section_alignment: u32,
    file_alignment: u32,
    size_of_headers: u32,
    number_of_rva_and_sizes: u32,
}

impl PeInfo {
    fn data_dir_offset(&self, index: usize) -> Option<usize> {
        (index < self.number_of_rva_and_sizes as usize)
            .then(|| self.opt_base + OPT_DATA_DIRECTORIES + index * 8)
    }
}

fn parse_pe(data: &[u8]) -> Result<PeInfo> {
    if rd_u16(data, 0)? != 0x5a4d {
        return Err("efistub: missing MZ signature".into());
    }
    let e_lfanew = rd_u32(data, 0x3c)? as usize;
    if rd_u32(data, e_lfanew)? != 0x0000_4550 {
        return Err("efistub: missing PE\\0\\0 signature".into());
    }
    let coff_base = e_lfanew + 4;
    let machine = rd_u16(data, coff_base)?;
    if machine != IMAGE_FILE_MACHINE_AMD64 {
        return Err(format!("efistub: machine {machine:#x} is not x86-64"));
    }
    let number_of_sections = rd_u16(data, coff_base + 2)?;
    let pointer_to_symbol_table = rd_u32(data, coff_base + 8)?;
    let size_of_optional_header = rd_u16(data, coff_base + 16)? as usize;
    let opt_base = coff_base + 20;
    if rd_u16(data, opt_base)? != PE32PLUS_MAGIC {
        return Err("efistub: optional header is not PE32+".into());
    }

    let info = PeInfo {
        coff_base,
        opt_base,
        number_of_sections,
        pointer_to_symbol_table,
        sect_offset: opt_base + size_of_optional_header,
        section_alignment: rd_u32(data, opt_base + OPT_SECTION_ALIGNMENT)?,
        file_alignment: rd_u32(data, opt_base + OPT_FILE_ALIGNMENT)?,
        size_of_headers: rd_u32(data, opt_base + OPT_SIZE_OF_HEADERS)?,
        number_of_rva_and_sizes: rd_u32(data, opt_base + OPT_NUMBER_OF_RVA_AND_SIZES)?,
    };
    if !info.section_alignment.is_power_of_two() || !info.file_alignment.is_power_of_two() {
        return Err("efistub: section/file alignment is not a power of two".into());
    }
    Ok(info)
}

#[derive(Debug, Clone)]
struct SectionHeader {
    name: [u8; 8],
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    pointer_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_linenumbers: u32,
    number_of_relocations: u16,
    number_of_linenumbers: u16,
    characteristics: u32,
}

impl SectionHeader {
    fn parse(data: &[u8], offset: usize) -> Result<SectionHeader> {
        Ok(SectionHeader {
            name: data
                .get(offset..offset + 8)
                .ok_or("section table runs past end of file")?
                .try_into()
                .unwrap(),
            virtual_size: rd_u32(data, offset + 8)?,
            virtual_address: rd_u32(data, offset + 12)?,
            size_of_raw_data: rd_u32(data, offset + 16)?,
            pointer_to_raw_data: rd_u32(data, offset + 20)?,
            pointer_to_relocations: rd_u32(data, offset + 24)?,
            pointer_to_linenumbers: rd_u32(data, offset + 28)?,
            number_of_relocations: rd_u16(data, offset + 32)?,
            number_of_linenumbers: rd_u16(data, offset + 34)?,
            characteristics: rd_u32(data, offset + 36)?,
        })
    }

    fn to_bytes(&self) -> [u8; SECTION_HEADER_SIZE] {
        let mut buf = [0u8; SECTION_HEADER_SIZE];
        buf[0..8].copy_from_slice(&self.name);
        buf[8..12].copy_from_slice(&self.virtual_size.to_le_bytes());
        buf[12..16].copy_from_slice(&self.virtual_address.to_le_bytes());
        buf[16..20].copy_from_slice(&self.size_of_raw_data.to_le_bytes());
        buf[20..24].copy_from_slice(&self.pointer_to_raw_data.to_le_bytes());
        buf[24..28].copy_from_slice(&self.pointer_to_relocations.to_le_bytes());
        buf[28..32].copy_from_slice(&self.pointer_to_linenumbers.to_le_bytes());
        buf[32..34].copy_from_slice(&self.number_of_relocations.to_le_bytes());
        buf[34..36].copy_from_slice(&self.number_of_linenumbers.to_le_bytes());
        buf[36..40].copy_from_slice(&self.characteristics.to_le_bytes());
        buf
    }

    fn raw_end(&self) -> u64 {
        self.pointer_to_raw_data as u64 + self.size_of_raw_data as u64
    }

    fn va_end(&self) -> u64 {
        self.virtual_address as u64 + self.virtual_size.max(self.size_of_raw_data) as u64
    }

    fn contains_rva(&self, rva: u32) -> bool {
        let start = self.virtual_address as u64;
        (start..start + self.virtual_size as u64).contains(&(rva as u64))
    }
}

fn rva_to_file_offset(sections: &[SectionHeader], rva: u32) -> Option<usize> {
    sections
        .iter()
        .find(|s| s.size_of_raw_data != 0 && s.contains_rva(rva))
        .map(|s| (s.pointer_to_raw_data + (rva - s.virtual_address)) as usize)
}

struct NewSection {
    name: &'static str,
    data: Vec<u8>,
}

/// Standard PE image checksum (as computed by imagehlp's CheckSumMappedFile).
fn pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    for (i, chunk) in data.chunks(2).enumerate() {
        let off = i * 2;
        if off == checksum_offset || off == checksum_offset + 2 {
            continue;
        }
        let word = if chunk.len() == 2 {
            u16::from_le_bytes([chunk[0], chunk[1]]) as u64
        } else {
            chunk[0] as u64
        };
        sum += word;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum as u32).wrapping_add(data.len() as u32)
}

// ---------------------------------------------------------------------------
// xen.cfg sanity check
//
// Xen's EFI loader only understands these keys; everything else is silently
// ignored.  Most importantly, dom0's command line is taken from the text after
// the file name on the `kernel=` line of the selected section, so a missing
// `kernel=` line means dom0 boots with an empty command line (no root=).
// ---------------------------------------------------------------------------

const XEN_CFG_KEYS: &[&str] = &[
    "chain", "default", "dtb", "kernel", "options", "ramdisk", "ucode", "video", "xsm",
];

fn check_xen_cfg(cfg: &[u8]) -> Vec<String> {
    let text = String::from_utf8_lossy(cfg);
    let mut warnings = Vec::new();
    let mut current = String::new();
    let mut default: Option<String> = None;
    let mut sections_with_kernel: Vec<String> = Vec::new();

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = name.trim().to_string();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            warnings.push(format!("xen.cfg:{}: not a key=value line, Xen ignores it", lineno + 1));
            continue;
        };
        let key = key.trim();
        if !XEN_CFG_KEYS.contains(&key) {
            warnings.push(format!(
                "xen.cfg:{}: '{key}=' is not a Xen EFI config key, Xen ignores it",
                lineno + 1
            ));
        }
        match key {
            "default" if current == "global" => default = Some(value.trim().to_string()),
            "kernel" => sections_with_kernel.push(current.clone()),
            _ => {}
        }
    }

    match default {
        None => warnings.push("xen.cfg: no default= in [global]".into()),
        Some(d) if !sections_with_kernel.contains(&d) => warnings.push(format!(
            "xen.cfg: section [{d}] has no kernel= line; dom0 will boot with an EMPTY command \
             line (put 'kernel=vmlinuz root=... <args>' there - the file name is ignored when \
             .kernel is embedded, the arguments are not)"
        )),
        _ => {}
    }
    warnings
}

// ---------------------------------------------------------------------------
// Output construction
// ---------------------------------------------------------------------------

/// Build a string table holding only the long section names, rewriting the
/// "/<offset>" names in `sections` to point into it.  Returns an empty table
/// if no section needs one.
fn minimal_string_table(efistub: &[u8], pe: &PeInfo, sections: &mut [SectionHeader]) -> Result<Vec<u8>> {
    let nsyms = rd_u32(efistub, pe.coff_base + 12)? as usize;
    let strtab = pe.pointer_to_symbol_table as usize + nsyms * 18;
    let strtab_size = rd_u32(efistub, strtab)? as usize;
    let mut table = vec![0u8; 4];
    for s in sections.iter_mut().filter(|s| s.name[0] == b'/') {
        let digits = s.name[1..].iter().take_while(|c| c.is_ascii_digit()).count();
        let idx: usize = std::str::from_utf8(&s.name[1..1 + digits])
            .ok()
            .and_then(|d| d.parse().ok())
            .ok_or("efistub: malformed long section name")?;
        if idx < 4 || idx >= strtab_size {
            return Err("efistub: long section name points outside the string table".into());
        }
        let start = strtab + idx;
        let len = efistub[start..strtab + strtab_size]
            .iter()
            .position(|&c| c == 0)
            .ok_or("efistub: unterminated long section name")?;
        let new_name = format!("/{}", table.len());
        table.extend_from_slice(&efistub[start..start + len + 1]);
        s.name = [0; 8];
        s.name[..new_name.len()].copy_from_slice(new_name.as_bytes());
    }
    if table.len() == 4 {
        return Ok(Vec::new());
    }
    let size = table.len() as u32;
    table[..4].copy_from_slice(&size.to_le_bytes());
    Ok(table)
}

fn build_output(
    efistub: &[u8],
    pe: &PeInfo,
    new_sections: &[NewSection],
    strip_symbols: bool,
) -> Result<Vec<u8>> {
    let file_align = pe.file_alignment as u64;
    let sect_align = pe.section_alignment as u64;

    let mut sections = (0..pe.number_of_sections as usize)
        .map(|i| SectionHeader::parse(efistub, pe.sect_offset + i * SECTION_HEADER_SIZE))
        .collect::<Result<Vec<_>>>()?;

    // Where the input's section data ends, and where its trailing data (COFF
    // symbol/string table) ends.  An existing Authenticode signature is dropped:
    // it would no longer be valid and would end up in the middle of the file.
    let sections_raw_end = sections
        .iter()
        .map(SectionHeader::raw_end)
        .max()
        .unwrap_or(0)
        .max(pe.size_of_headers as u64) as usize;

    let mut tail_end = efistub.len();
    if let Some(off) = pe.data_dir_offset(DIR_SECURITY) {
        let cert_off = rd_u32(efistub, off)? as usize;
        if cert_off != 0 {
            eprintln!("note: efistub is already signed; dropping its signature (re-sign the output)");
            if cert_off < sections_raw_end || cert_off > efistub.len() {
                return Err("efistub: certificate table overlaps section data".into());
            }
            tail_end = cert_off;
        }
    }
    if sections_raw_end > tail_end {
        return Err("efistub: section data runs past end of file".into());
    }
    let stripped_tail;
    let tail = if strip_symbols && pe.pointer_to_symbol_table != 0 {
        stripped_tail = minimal_string_table(efistub, pe, &mut sections)?;
        &stripped_tail[..]
    } else {
        &efistub[sections_raw_end..tail_end]
    };

    // New header area: section table grows by one entry per new section.
    let total_sections = sections.len() + new_sections.len();
    let header_end = (pe.sect_offset + total_sections * SECTION_HEADER_SIZE) as u64;
    let new_size_of_headers = align_up(header_end, file_align).max(pe.size_of_headers as u64);
    let first_va = sections.iter().map(|s| s.virtual_address).min().unwrap_or(u32::MAX);
    if new_size_of_headers > first_va as u64 {
        return Err(format!(
            "no room for {total_sections} section headers below the first section at RVA {first_va:#x}"
        ));
    }
    let shift = new_size_of_headers - pe.size_of_headers as u64;

    for s in sections.iter_mut().filter(|s| s.size_of_raw_data != 0) {
        s.pointer_to_raw_data = to_u32(s.pointer_to_raw_data as u64 + shift, "PointerToRawData")?;
    }

    // New sections go after the highest existing RVA, each on a SectionAlignment
    // boundary, with file data packed directly after the existing section data.
    let mut next_va = align_up(sections.iter().map(SectionHeader::va_end).max().unwrap_or(0), sect_align);
    let mut next_raw = align_up(sections_raw_end as u64 + shift, file_align);
    let mut added_init_data: u64 = 0;
    let mut new_headers = Vec::new();

    for ns in new_sections {
        if ns.name.len() > 8 {
            return Err(format!("section name {} is longer than 8 bytes", ns.name));
        }
        let mut name = [0u8; 8];
        name[..ns.name.len()].copy_from_slice(ns.name.as_bytes());

        let raw_size = align_up(ns.data.len() as u64, file_align);
        new_headers.push(SectionHeader {
            name,
            virtual_size: to_u32(ns.data.len() as u64, ns.name)?,
            virtual_address: to_u32(next_va, "VirtualAddress")?,
            size_of_raw_data: to_u32(raw_size, ns.name)?,
            pointer_to_raw_data: to_u32(next_raw, "PointerToRawData")?,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        });
        added_init_data += raw_size;
        next_va = align_up(next_va + ns.data.len() as u64, sect_align);
        next_raw += raw_size;
    }
    let size_of_image = to_u32(next_va, "SizeOfImage")?;

    // --- assemble ---------------------------------------------------------
    let mut out = Vec::with_capacity(next_raw as usize + tail.len());
    out.extend_from_slice(&efistub[..pe.sect_offset]);
    for h in sections.iter().chain(new_headers.iter()) {
        out.extend_from_slice(&h.to_bytes());
    }
    pad_to(&mut out, new_size_of_headers as usize);
    out.extend_from_slice(&efistub[pe.size_of_headers as usize..sections_raw_end]);

    for (h, ns) in new_headers.iter().zip(new_sections) {
        pad_to(&mut out, h.pointer_to_raw_data as usize);
        out.extend_from_slice(&ns.data);
        pad_to(&mut out, h.raw_end() as usize);
    }

    // Symbol/string table goes after the last section so there are no
    // unhashed gaps between sections.  It must be kept: the string table
    // holds long section names such as ".data.read_mostly" ("/4").
    let tail_offset = out.len();
    out.extend_from_slice(tail);

    // --- patch headers ----------------------------------------------------
    patch_u16(&mut out, pe.coff_base + 2, total_sections as u16);
    if strip_symbols && pe.pointer_to_symbol_table != 0 {
        // NumberOfSymbols = 0; the string table (if any) directly follows "the symbols".
        let ptr = if tail.is_empty() { 0 } else { to_u32(tail_offset as u64, "PointerToSymbolTable")? };
        patch_u32(&mut out, pe.coff_base + 8, ptr);
        patch_u32(&mut out, pe.coff_base + 12, 0);
    } else if pe.pointer_to_symbol_table != 0 {
        let rel = (pe.pointer_to_symbol_table as usize)
            .checked_sub(sections_raw_end)
            .ok_or("efistub: symbol table lies inside section data")?;
        patch_u32(&mut out, pe.coff_base + 8, to_u32((tail_offset + rel) as u64, "PointerToSymbolTable")?);
    }

    let opt = pe.opt_base;
    let init_data = rd_u32(&out, opt + OPT_SIZE_OF_INITIALIZED_DATA)? as u64 + added_init_data;
    patch_u32(&mut out, opt + OPT_SIZE_OF_INITIALIZED_DATA, init_data.min(u32::MAX as u64) as u32);
    patch_u32(&mut out, opt + OPT_SIZE_OF_IMAGE, size_of_image);
    patch_u32(&mut out, opt + OPT_SIZE_OF_HEADERS, new_size_of_headers as u32);
    if let Some(off) = pe.data_dir_offset(DIR_SECURITY) {
        patch_u32(&mut out, off, 0);
        patch_u32(&mut out, off + 4, 0);
    }

    // Debug directory entries carry a *file* pointer to their payload (Xen's
    // build-id CodeView record), which moved by `shift`.
    if let Some(off) = pe.data_dir_offset(DIR_DEBUG) {
        let rva = rd_u32(&out, off)?;
        let size = rd_u32(&out, off + 4)? as usize;
        if rva != 0 && size != 0 {
            let dir = rva_to_file_offset(&sections, rva).ok_or("debug directory RVA not in any section")?;
            for i in 0..size / DEBUG_DIRECTORY_ENTRY_SIZE {
                let ptr_off = dir + i * DEBUG_DIRECTORY_ENTRY_SIZE + 24;
                let ptr = rd_u32(&out, ptr_off)?;
                if ptr != 0 {
                    patch_u32(&mut out, ptr_off, to_u32(ptr as u64 + shift, "debug PointerToRawData")?);
                }
            }
        }
    }

    let checksum_offset = opt + OPT_CHECKSUM;
    let checksum = pe_checksum(&out, checksum_offset);
    patch_u32(&mut out, checksum_offset, checksum);

    Ok(out)
}

fn read(path: &Path, what: &str) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| format!("failed to read {what} {}: {e}", path.display()))
}

fn ramdisk(args: &Args) -> Result<Vec<u8>> {
    let image = read(&args.ramdisk, "ramdisk image")?;
    if args.initrd_drop.is_empty() && args.initrd_omit_module.is_empty() {
        return Ok(image);
    }
    let filter = initrd::Filter {
        drop: args.initrd_drop.clone(),
        omit_modules: args.initrd_omit_module.clone(),
    };
    let (out, stats) = initrd::filter(&image, &filter)?;
    for line in &stats.log {
        eprintln!("ramdisk: {line}");
    }
    eprintln!(
        "ramdisk: dropped {} entries ({} bytes uncompressed, {} whole archive(s)); {} -> {} bytes",
        stats.dropped_entries,
        stats.dropped_bytes,
        stats.dropped_archives,
        image.len(),
        out.len()
    );
    if stats.dropped_entries == 0 {
        eprintln!("warning: ramdisk filters matched nothing");
    }
    Ok(out)
}

fn run() -> Result<()> {
    let args = Args::parse();

    let efistub = read(&args.efistub, "EFI boot stub")?;
    let config = read(&args.xencfg, "configuration")?;
    let pe = parse_pe(&efistub)?;

    for w in check_xen_cfg(&config) {
        eprintln!("warning: {w}");
    }

    let mut new_sections = vec![
        NewSection { name: ".config", data: config },
        NewSection { name: ".kernel", data: read(&args.kernel, "kernel image")? },
        NewSection { name: ".ramdisk", data: ramdisk(&args)? },
        NewSection { name: ".ucode", data: read(&args.ucode, "microcode image")? },
    ];
    if let Some(p) = &args.sbat {
        new_sections.push(NewSection { name: ".sbat", data: read(p, "SBAT")? });
    }
    if let Some(p) = &args.osrel {
        new_sections.push(NewSection { name: ".osrel", data: read(p, "os-release")? });
    }

    let out = build_output(&efistub, &pe, &new_sections, args.strip_symbols)?;
    fs::write(&args.outfile, &out)
        .map_err(|e| format!("failed to write {}: {e}", args.outfile.display()))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xenuki: {e}");
            ExitCode::FAILURE
        }
    }
}
