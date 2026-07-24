use clap::Parser;
use std::path::PathBuf;
use std::fs;
use std::path::Path;


/// A UKI Kernel Image for a Xen dom0 Linux host
/// Learning RUST w/ Claude
/// Date: Fri Jul 24 08:01:10 AM CDT 2026

#[derive(Parser, Debug)]
#[command(name = "uki-packer", version, about)]

struct Args {
    /// Path top kernel img
    #[arg(short, long)]
    kernel: PathBuf,

    /// Path to ramfs
    #[arg(short, long)]
    ramfs: PathBuf,

    /// Path to kernel cmdline.d
    #[arg(short, long)]
    cmdline: PathBuf,

    /// UKI output filename
    #[arg(short, long)]
    output: PathBuf,

    /// Path to systemd-boot efi boot stub
    #[arg(short,long)]
    efistub: PathBuf,

    /// Path to kernel cmdline.d
    #[arg(short, long)]
    xencfg: PathBuf,

}

fn build_cmdline(dir: &Path) -> std::io::Result<String> {
    
    // read dirents - this call can fail, hense Result

    let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok())                 // skip entries that errored mid -iteration
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

fn main() {
    let args = Args::parse();

    let cmdline = build_cmdline(&args.cmdline)
        .expect ("failed to read the cmdline.d directory");

    let kernel_data = read_binary_file(&args.kernel)
        .expect("failed to read kernel image");


    let ramfs_data = read_binary_file(&args.ramfs)
        .expect("failed to read ramfsi mage");

    let stub_data = read_binary_file(&args.stub)
        .expect("failed to read the EFI boot stub");

    let dos_header = parse_dos_header(&stub_data);
    println!("Magic: {:#x}", dos_header.e_magic);
    println!("PE Header offset: {:#x}", dos_header.e_lfanew);

    let coff_header = parse_coff_header(&stub_data, dos_header.e_lfanew);
    println!("{:#?}", coff_header);

    let sect_offset = section_table_offset(dos_header.e_lfanew, &coff_header);
    let sect_end = sect_offset + (coff_header.number_of_sections as usize * 40); // each section header is 40 bytes
    println!("Section table: {:#x} .. {:#x}", sect_offset, sect_end);
    println!("Number of sections: {}", coff_header.number_of_sections);

    println!("Final cmdline: {}", cmdline);
    println!("Kernel Size: {} bytes", kernel_data.len());
    println!("Initrd Size: {} bytes", ramfs_data.len());

    
}
