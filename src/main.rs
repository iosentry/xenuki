///                 This code generates a monolithic UEFI / SecureBoot compliant
///                 Xen Hypervisor Domain0 Linux Unified Kernel Image (UKI)
///                 This design allows provides for the validation and assurance 
///                 initramfs contents by packing the entire hypervisor and host OS
///                 components together where thet can be signed with the Administrators
///                 SecureBoot Keys.
///  
///                 roman@systemwarfare.net
///                 Date: Fri Jul 24 08:01:10 AM CDT 2026

use clap::Parser;
use std::path::PathBuf;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(name = "uki-packer", version, about)]
struct Args {
    /// Path top kernel img
    #[arg(short, long)]
    kernel: PathBuf,

    /// Path to ramdisk
    #[arg(short, long)]
    ramdisk: PathBuf,

    /// Path to kernel cmdline.d
 //   #[arg(short, long)]
 //   cmdline: PathBuf,

    /// UKI output filename
    #[arg(short, long)]
    outfile: PathBuf,

    /// Path to systemd-boot efi boot stub
    #[arg(short,long)]
    efistub: PathBuf,

    /// Path to the xen.cfg dom0 configuration file
    #[arg(short, long)]
    xencfg: PathBuf,

    /// Path top processor microcode img
    #[arg(short, long)]
    ucode: PathBuf,

}

/*
fn build_cmdline(dir: &Path) -> std::io::Result<String> {
    
    // read dirents - this call can fail, hense Result

    let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())            // skip entries that errored mid -iteration
        .map(|entry| entry.path())                      // DirEnt -> PathBuf
        .filter(|path| path.is_file())                  // Skip subdirs
        .collect();

    // sort lexicographically by full path 
    entries.sort();

    // read files etc
    let mut fragments: Vec<String> = Vec::new();
    for path in &entries {
        let contents = fs::read_to_string(path)?;
        fragments.push(contents.trim().to_string());
    }

    Ok(fragments.join(" "))
}
*/

fn read_binary_file(path: &Path) -> std::io::Result<Vec<u8>> {
    fs::read(path)
}

#[repr(C)]
#[derive(Debug)]
struct CoffHeader {
    signature: u32,
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

fn parse_coff_header(data: &[u8], e_lfanew: u32) -> CoffHeader {
    let offset = e_lfanew as usize;

    CoffHeader {
        signature: u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()),
        machine: u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap()),
        number_of_sections: u16::from_le_bytes(data[offset + 6..offset + 8].try_into().unwrap()),
        time_date_stamp: u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()),
        pointer_to_symbol_table: u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap()),
        number_of_symbols: u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap()),
        size_of_optional_header: u16::from_le_bytes(data[offset + 20..offset + 22].try_into().unwrap()),
        characteristics: u16::from_le_bytes(data[offset + 22..offset + 24].try_into().unwrap()),
    }
}
    
#[repr(C)]
#[derive(Debug)]
struct DosHeader {
    e_magic: u16,        // Must be 'MZ' 0x5A4D
    _reserved: [u8; 58], 
    e_lfanew: u32,       // offset to PE header
}

fn parse_dos_header(data: &[u8]) -> DosHeader {
    DosHeader {
        e_magic: u16::from_le_bytes([data[0], data[1]]),
        _reserved: data[2..60].try_into().unwrap(),
        e_lfanew: u32::from_le_bytes(data[60..64].try_into().unwrap()),
    }
}

fn section_table_offset(e_lfanew: u32, coff: &CoffHeader) -> usize {
    e_lfanew as usize + 4 + 20 + coff.size_of_optional_header as usize
}

#[repr(C)]
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
    fn clone_with_shifted_ptr(&self, shift: u32) -> SectionHeader {
        let mut copy = self.clone();
        if copy.size_of_raw_data == 0 {
            copy
        } else {
            copy.pointer_to_raw_data += shift;
            copy
        }
    }   
}

fn parse_section_header(data: &[u8], offset: usize) -> SectionHeader {
    SectionHeader {
        name: data[offset..offset + 8].try_into().unwrap(),
        virtual_size: u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()),
        virtual_address: u32::from_le_bytes(data[offset + 12..offset + 16].try_into().unwrap()),
        size_of_raw_data: u32::from_le_bytes(data[offset + 16..offset + 20].try_into().unwrap()),
        pointer_to_raw_data: u32::from_le_bytes(data[offset + 20..offset + 24].try_into().unwrap()),
        pointer_to_relocations: u32::from_le_bytes(data[offset + 24..offset + 28].try_into().unwrap()),
        pointer_to_linenumbers: u32::from_le_bytes(data[offset + 28..offset + 32].try_into().unwrap()),
        number_of_relocations: u16::from_le_bytes(data[offset + 32..offset + 34].try_into().unwrap()),
        number_of_linenumbers: u16::from_le_bytes(data[offset + 34..offset + 36].try_into().unwrap()),
        characteristics: u32::from_le_bytes(data[offset + 36..offset + 40].try_into().unwrap()),
    }
}

fn section_name(section: &SectionHeader, data: &[u8], coff: &CoffHeader) -> String {
    let raw = &section.name;

    // Short name: null-padded ASCII, no lookup needed
    if raw[0] != b'/' {
        let end = raw.iter().position(|&b| b == 0).unwrap_or(8);
        return String::from_utf8_lossy(&raw[..end]).to_string();
    }

    // Long name: "/N" where N is a decimal offset into the string table
    let offset_str = String::from_utf8_lossy(&raw[1..])
        .trim_end_matches('\0')
        .to_string();
    let string_table_offset: usize = offset_str.parse().unwrap_or(0);

    // String table follows the symbol table: each symbol entry is 18 bytes
    let symbol_table_start = coff.pointer_to_symbol_table as usize;
    let string_table_start = symbol_table_start + (coff.number_of_symbols as usize * 18);
    let name_start = string_table_start + string_table_offset;

    let end = data[name_start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| name_start + p)
        .unwrap_or(name_start);

    String::from_utf8_lossy(&data[name_start..end]).to_string()
}

#[repr(C)]
#[derive(Debug)]
struct OptionalHeaderInfo {
    section_alignment: u32,
    file_alignment: u32,
    size_of_image: u32,
    size_of_headers: u32,
}

fn parse_optional_header(data: &[u8], e_lfanew: u32) -> OptionalHeaderInfo {
    let base = e_lfanew as usize + 24; // skip PE sig (4) + COFF header (20)

    OptionalHeaderInfo {
        section_alignment: u32::from_le_bytes(data[base + 32..base + 36].try_into().unwrap()),
        file_alignment: u32::from_le_bytes(data[base + 36..base + 40].try_into().unwrap()),
        size_of_image: u32::from_le_bytes(data[base + 56..base + 60].try_into().unwrap()),
        size_of_headers: u32::from_le_bytes(data[base + 60..base + 64].try_into().unwrap()),
    }
}

fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) / alignment * alignment
}

#[repr(C)]
#[derive(Debug)]
struct NewSection {
    name: String,
    data: Vec<u8>,
}

fn build_section_headers(
    new_sections: &[NewSection],
    last_va_end: u32,
    last_raw_end: u32,
    section_alignment: u32,
    file_alignment: u32,
) -> Vec<SectionHeader> {
    let mut headers = Vec::new();
    let mut next_va = align_up(last_va_end, section_alignment);
    let mut next_raw = align_up(last_raw_end, file_alignment);

    for section in new_sections {
        let mut name_bytes = [0u8; 8];
        let name_slice = section.name.as_bytes();
        let len = name_slice.len().min(8);
        name_bytes[..len].copy_from_slice(&name_slice[..len]);

        let raw_size = align_up(section.data.len() as u32, file_alignment);
        let virtual_size = section.data.len() as u32;

        headers.push(SectionHeader {
            name: name_bytes,
            virtual_size,
            virtual_address: next_va,
            size_of_raw_data: raw_size,
            pointer_to_raw_data: next_raw,
            pointer_to_relocations: 0,
            pointer_to_linenumbers: 0,
            number_of_relocations: 0,
            number_of_linenumbers: 0,
            characteristics: 0x40000040, // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        });

        next_va = align_up(next_va + virtual_size, section_alignment);
        next_raw = align_up(next_raw + raw_size, file_alignment);
    }

    headers
}

fn patch_u16(buf: &mut Vec<u8>, offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn patch_u32(buf: &mut Vec<u8>, offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}


fn section_header_bytes(h: &SectionHeader) -> [u8; 40] {
    let mut buf = [0u8; 40];
    buf[0..8].copy_from_slice(&h.name);
    buf[8..12].copy_from_slice(&h.virtual_size.to_le_bytes());
    buf[12..16].copy_from_slice(&h.virtual_address.to_le_bytes());
    buf[16..20].copy_from_slice(&h.size_of_raw_data.to_le_bytes());
    buf[20..24].copy_from_slice(&h.pointer_to_raw_data.to_le_bytes());
    buf[24..28].copy_from_slice(&h.pointer_to_relocations.to_le_bytes());
    buf[28..32].copy_from_slice(&h.pointer_to_linenumbers.to_le_bytes());
    buf[32..34].copy_from_slice(&h.number_of_relocations.to_le_bytes());
    buf[34..36].copy_from_slice(&h.number_of_linenumbers.to_le_bytes());
    buf[36..40].copy_from_slice(&h.characteristics.to_le_bytes());
    buf
}


fn build_output(
    efistub_data: &[u8],
    dos_header: &DosHeader,
    coff_header: &CoffHeader,
    opt_header: &OptionalHeaderInfo,
    sect_offset: usize,
    existing_sections: &[SectionHeader],
    new_headers: &[SectionHeader],
    new_sections: &[NewSection],
) -> Vec<u8> {
    let file_alignment = opt_header.file_alignment;
    let header_growth = new_headers.len() * 40;

    // 1. New SizeOfHeaders: old headers region + growth, aligned to FileAlignment
    let old_headers_end = opt_header.size_of_headers;
    let new_size_of_headers = align_up(old_headers_end + header_growth as u32, file_alignment);
    let shift = new_size_of_headers - old_headers_end; // how far ALL existing raw data moves
    println!("SHIFTING: {shift}");

    // 2. Start building the output buffer
    let mut out = Vec::new();

    // Copy everything up to the section table unchanged (DOS header, PE sig, COFF header, optional header)
    out.extend_from_slice(&efistub_data[..sect_offset]);

    // 3. Write existing section headers, with PointerToRawData shifted
    for section in existing_sections {
        let mut patched = section.clone_with_shifted_ptr(shift); // see note below
        out.extend_from_slice(&section_header_bytes(&patched));
    }

    // 4. Write new section headers (their offsets were already computed relative to
    //    the OLD file layout's raw data — but since header growth happens at the very
    //    start, and new sections are appended at the very end, their offsets need the
    //    same shift applied too)
    for header in new_headers {
        let mut patched = header.clone();
        patched.pointer_to_raw_data += shift;
        out.extend_from_slice(&section_header_bytes(&patched));
    }

    // 5. Pad out to new_size_of_headers with zeros
    while out.len() < new_size_of_headers as usize {
        out.push(0);
    }

    // 6. Copy existing section raw data unchanged (just relocated as a block)
    out.extend_from_slice(&efistub_data[old_headers_end as usize..]);

    // 7. Append new section raw data, each padded to its aligned size
    for (header, section) in new_headers.iter().zip(new_sections.iter()) {
        out.extend_from_slice(&section.data);
        let padded_size = header.size_of_raw_data as usize;
        while out.len() % file_alignment as usize != 0 {
            out.push(0);
        }
        // ensure we match this section's declared raw size exactly
        let target_len = header.pointer_to_raw_data as usize + padded_size;
        while out.len() < target_len {
            out.push(0);
        }
    }

    // 8. Patch header fields: NumberOfSections, SizeOfImage, SizeOfHeaders
    let coff_base = dos_header.e_lfanew as usize + 4;
    patch_u16(&mut out, coff_base + 2, coff_header.number_of_sections + new_headers.len() as u16);

    let opt_base = dos_header.e_lfanew as usize + 24;
    let last = new_headers.last().unwrap();
    let new_size_of_image = align_up(last.virtual_address + last.virtual_size, opt_header.section_alignment);
    patch_u32(&mut out, opt_base + 56, new_size_of_image);
    patch_u32(&mut out, opt_base + 60, new_size_of_headers);

    out
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let mut sections: Vec<SectionHeader> = Vec::new();

//    let cmdline = build_cmdline(&args.cmdline)
//        .expect ("failed to read the cmdline.d directory");

    let kernel_data = read_binary_file(&args.kernel)
        .expect("failed to read kernel image");

    let ucode_data = read_binary_file(&args.ucode)
        .expect("failed to read microcode image");

    let ramdisk_data = read_binary_file(&args.ramdisk)
        .expect("failed to read ramdisk image");

    let efistub_data = read_binary_file(&args.efistub)
        .expect("failed to read the EFI boot stub");

    let dos_header = parse_dos_header(&efistub_data);
    println!("Magic: {:#x}", dos_header.e_magic);
    println!("PE Header offset: {:#x}", dos_header.e_lfanew);

    let coff_header = parse_coff_header(&efistub_data, dos_header.e_lfanew);
    println!("{:#?}", coff_header);

    let sect_offset = section_table_offset(dos_header.e_lfanew, &coff_header);
    let sect_end = sect_offset + (coff_header.number_of_sections as usize * 40); // each section header is 40 bytes
    println!("Section table: {:#x} .. {:#x}", sect_offset, sect_end);
    println!("Number of sections: {}", coff_header.number_of_sections);

    let opt_header = parse_optional_header(&efistub_data, dos_header.e_lfanew);
    println!("{:#?}", opt_header);

    for i in 0..coff_header.number_of_sections {
        let entry_offset = sect_offset + (i as usize * 40);
        sections.push(parse_section_header(&efistub_data, entry_offset));
    }

    let new_sections = vec![
        NewSection { name: ".config".to_string(), data: fs::read(&args.xencfg).expect("read config") },
        NewSection { name: ".kernel".to_string(), data: kernel_data.clone() },
        NewSection { name: ".ramdisk".to_string(), data: ramdisk_data.clone() },
        NewSection { name: ".ucode".to_string(), data: ucode_data.clone() },
    ];

    // find the last existing section (.reloc) to compute where new ones begin
    let last = &sections[sections.len() - 1]; // assuming you've collected parsed sections into `sections: Vec<SectionHeader>`
    let last_va_end = last.virtual_address + last.virtual_size;
    let last_raw_end = last.pointer_to_raw_data + last.size_of_raw_data;

    let new_headers = build_section_headers(
        &new_sections,
        last_va_end,
        last_raw_end,
        opt_header.section_alignment,
        opt_header.file_alignment,
    );

    for h in &new_headers {
        println!(
            "{:<10} VA={:#x} VSize={:#x} RawPtr={:#x} RawSize={:#x}",
            section_name(h, &efistub_data, &coff_header),
            h.virtual_address, h.virtual_size, h.pointer_to_raw_data, h.size_of_raw_data
        );
    }

    let new_number_of_sections = coff_header.number_of_sections + new_headers.len() as u16;

    let last_new = new_headers.last().unwrap();
    let new_size_of_image = align_up(
        last_new.virtual_address + last_new.virtual_size,
        opt_header.section_alignment,
    );

    let xenuki: Vec<u8> = build_output(
        &efistub_data, 
        &dos_header, 
        &coff_header, 
        &opt_header,
        sect_offset,
        &sections,
        &new_headers,
        &new_sections);

    fs::write(&args.outfile, xenuki)?;
    Ok(())
}
