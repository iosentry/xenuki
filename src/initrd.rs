//! Initramfs filtering.
//!
//! A Linux initramfs is a sequence of cpio "newc" archives, each optionally
//! compressed, separated by zero padding.  Typically (dracut, mkinitcpio):
//!
//!   [ uncompressed early cpio (kernel/x86/microcode/...) ] [ compressed main cpio ]
//!
//! This module drops entries by path pattern without ever extracting to disk
//! (which would lose ownership, device nodes and hard links), and re-emits
//! each archive with the compression it came in.  An archive left with no
//! non-directory entries is removed entirely.
//!
//! Modules removed with `omit_modules` are also blacklisted inside the
//! initramfs (usr/lib/modprobe.d/xenuki-omit.conf) so udev does not try to
//! load a module whose file is gone.  The real root's modprobe config is not
//! touched, so the module still loads normally after switch-root.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::process::{Command, Stdio};

type Result<T> = std::result::Result<T, String>;

const NEWC_HEADER_LEN: usize = 110;
const TRAILER: &str = "TRAILER!!!";
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const BLACKLIST_FILE: &str = "usr/lib/modprobe.d/xenuki-omit.conf";

#[derive(Clone, Copy, Debug, PartialEq)]
enum Compression {
    None,
    Zstd,
    Gzip,
    Xz,
}

impl Compression {
    fn detect(data: &[u8]) -> Result<Compression> {
        Ok(match data {
            [b'0', b'7', b'0', b'7', b'0', b'1' | b'2', ..] => Compression::None,
            [0x28, 0xb5, 0x2f, 0xfd, ..] => Compression::Zstd,
            [0x1f, 0x8b, ..] => Compression::Gzip,
            [0xfd, b'7', b'z', b'X', b'Z', 0x00, ..] => Compression::Xz,
            _ => {
                return Err(format!(
                    "initramfs: unsupported data (magic {:02x?}); only cpio, zstd, gzip and xz are handled",
                    &data[..data.len().min(6)]
                ));
            }
        })
    }

    fn name(self) -> &'static str {
        match self {
            Compression::None => "uncompressed",
            Compression::Zstd => "zstd",
            Compression::Gzip => "gzip",
            Compression::Xz => "xz",
        }
    }

    /// (decompress, compress) command lines.  xz must use CRC32 for the kernel.
    fn commands(self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            Compression::None => (&[], &[]),
            Compression::Zstd => (&["zstd", "-dcq"], &["zstd", "-cq", "-19", "-T0"]),
            Compression::Gzip => (&["gzip", "-dc"], &["gzip", "-cn9"]),
            Compression::Xz => (&["xz", "-dc"], &["xz", "-c", "--check=crc32", "-T0"]),
        }
    }
}

/// Run `argv` with `input` on stdin and return its stdout.
fn pipe_through(argv: &[&str], input: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new(argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", argv[0]))?;
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let output = std::thread::scope(|s| {
        s.spawn(move || {
            // A write error shows up as a failed exit status below.
            let _ = stdin.write_all(input);
        });
        let mut out = Vec::new();
        stdout.read_to_end(&mut out).map(|_| out)
    })
    .map_err(|e| format!("{}: {e}", argv[0]))?;
    let status = child.wait().map_err(|e| format!("{}: {e}", argv[0]))?;
    if !status.success() {
        return Err(format!("`{}` failed ({status})", argv.join(" ")));
    }
    Ok(output)
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

struct Entry<'a> {
    raw: &'a [u8], // header + name + data, including padding (a multiple of 4)
    name: String,
    mode: u32,
    ino: u32,
    nlink: u32,
    dev: (u32, u32),
    filesize: usize,
}

impl Entry<'_> {
    fn file_type(&self) -> u32 {
        self.mode & S_IFMT
    }
}

fn hex_field(data: &[u8], off: usize, index: usize) -> Result<u32> {
    let start = off + 6 + index * 8;
    let s = data
        .get(start..start + 8)
        .and_then(|b| std::str::from_utf8(b).ok())
        .ok_or_else(|| format!("cpio: truncated header at {off:#x}"))?;
    u32::from_str_radix(s, 16).map_err(|_| format!("cpio: bad header field at {off:#x}"))
}

/// Parse one newc archive starting at `off`; returns its entries (trailer
/// excluded) and the offset just past the trailer.
fn parse_archive(data: &[u8], mut off: usize) -> Result<(Vec<Entry<'_>>, usize)> {
    let mut entries = Vec::new();
    loop {
        match data.get(off..off + 6) {
            Some(b"070701") | Some(b"070702") => {}
            _ => return Err(format!("cpio: bad magic at {off:#x}")),
        }
        let ino = hex_field(data, off, 0)?;
        let mode = hex_field(data, off, 1)?;
        let nlink = hex_field(data, off, 4)?;
        let filesize = hex_field(data, off, 6)? as usize;
        let dev = (hex_field(data, off, 7)?, hex_field(data, off, 8)?);
        let namesize = hex_field(data, off, 11)? as usize;
        let name_start = off + NEWC_HEADER_LEN;
        let data_start = align4(name_start + namesize);
        let end = align4(data_start + filesize);
        if namesize == 0 || end > data.len() {
            return Err(format!("cpio: entry at {off:#x} runs past end of data"));
        }
        let name = String::from_utf8_lossy(&data[name_start..name_start + namesize - 1]).into_owned();
        if name == TRAILER {
            return Ok((entries, end));
        }
        entries.push(Entry { raw: &data[off..end], name, mode, ino, nlink, dev, filesize });
        off = end;
    }
}

fn newc_entry(name: &str, mode: u32, nlink: u32, ino: u32, data: &[u8]) -> Vec<u8> {
    let namesize = name.len() + 1;
    let mut e = format!(
        "070701{ino:08x}{mode:08x}{:08x}{:08x}{nlink:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{namesize:08x}{:08x}",
        0, 0, 0, data.len(), 0, 0, 0, 0, 0
    )
    .into_bytes();
    e.extend_from_slice(name.as_bytes());
    e.push(0);
    e.resize(align4(e.len()), 0);
    e.extend_from_slice(data);
    e.resize(align4(e.len()), 0);
    e
}

/// `*` matches any run of characters, including '/'.
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t, mut star, mut mark) = (0, 0, None, 0);
    while t < text.len() {
        if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if p < pattern.len() && pattern[p] == text[t] {
            p += 1;
            t += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&c| c == b'*')
}

pub struct Filter {
    /// Paths (relative, e.g. "usr/lib/firmware/nvidia") or `*` globs.  A
    /// pattern matching a directory also drops everything below it.
    pub drop: Vec<String>,
    /// Module names; their .ko files are dropped and they are blacklisted.
    pub omit_modules: Vec<String>,
}

impl Filter {
    fn module_patterns(&self) -> Vec<String> {
        self.omit_modules
            .iter()
            .flat_map(|m| {
                let alt = m.replace('-', "_");
                let alt2 = m.replace('_', "-");
                [m.clone(), alt, alt2]
                    .into_iter()
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .map(|n| format!("usr/lib/modules/*/{n}.ko*"))
            })
            .collect()
    }

    fn matches(patterns: &[String], name: &str) -> bool {
        let name = name.trim_start_matches("./").trim_start_matches('/');
        // match the path itself or any ancestor directory of it
        let mut prefixes = name.match_indices('/').map(|(i, _)| &name[..i]).collect::<Vec<_>>();
        prefixes.push(name);
        patterns.iter().any(|p| {
            let p = p.trim_start_matches('/');
            prefixes.iter().any(|pre| glob(p.as_bytes(), pre.as_bytes()))
        })
    }
}

#[derive(Default)]
pub struct Stats {
    pub dropped_entries: usize,
    pub dropped_bytes: u64,
    pub dropped_archives: usize,
    pub log: Vec<String>,
}

/// Filter the entries of one decompressed stream (possibly several archives).
/// Returns None if nothing but directories is left.
fn filter_stream(
    data: &[u8],
    filter: &Filter,
    add_blacklist: bool,
    stats: &mut Stats,
) -> Result<Option<Vec<u8>>> {
    let mut patterns = filter.drop.clone();
    patterns.extend(filter.module_patterns());

    let mut archives: Vec<Vec<u8>> = Vec::new();
    let mut off = 0;
    let mut kept_files = 0usize;
    let mut omitted_modules = HashSet::new();
    let mut max_ino = 0u32;
    let mut names = HashSet::new();

    while off < data.len() {
        let (entries, end) = parse_archive(data, off)?;

        // Hard links: only one entry of a group carries the data, so a group
        // must be kept or dropped as a whole.
        let mut groups: HashMap<(u32, u32, u32), (usize, usize)> = HashMap::new();
        let drop: Vec<bool> = entries.iter().map(|e| Filter::matches(&patterns, &e.name)).collect();
        for (e, &d) in entries.iter().zip(&drop) {
            if e.file_type() == S_IFREG && e.nlink > 1 {
                let g = groups.entry((e.dev.0, e.dev.1, e.ino)).or_default();
                if d { g.0 += 1 } else { g.1 += 1 }
            }
        }
        for (e, &d) in entries.iter().zip(&drop) {
            if d && e.file_type() == S_IFREG && e.nlink > 1 {
                if groups[&(e.dev.0, e.dev.1, e.ino)].1 != 0 {
                    return Err(format!("initramfs: '{}' is hard-linked to a kept file; widen the pattern", e.name));
                }
            }
        }

        let mut archive = Vec::new();
        for (e, d) in entries.iter().zip(drop) {
            max_ino = max_ino.max(e.ino);
            if d {
                stats.dropped_entries += 1;
                stats.dropped_bytes += e.filesize as u64;
                if e.name.starts_with("usr/lib/modules/") && e.name.contains(".ko") {
                    let base = e.name.rsplit('/').next().unwrap();
                    omitted_modules.insert(base[..base.find(".ko").unwrap()].replace('-', "_"));
                }
                continue;
            }
            if e.file_type() != S_IFDIR {
                kept_files += 1;
            }
            names.insert(e.name.trim_start_matches("./").to_string());
            archive.extend_from_slice(e.raw);
        }
        if !archive.is_empty() {
            archives.push(archive);
        }
        off = end;
        // zero padding between concatenated archives
        while off < data.len() && data[off] == 0 {
            off += 1;
        }
    }

    for m in &filter.omit_modules {
        if !omitted_modules.contains(&m.replace('-', "_")) && add_blacklist {
            stats.log.push(format!("module '{m}' not found in initramfs"));
        }
    }

    if add_blacklist && !omitted_modules.is_empty() {
        let mut mods: Vec<_> = omitted_modules.into_iter().collect();
        mods.sort();
        let mut text = String::from("# Added by xenuki: module files removed from this initramfs.\n");
        for m in &mods {
            text += &format!("blacklist {m}\n");
        }
        // Appended to the last archive (before its trailer, so cpio/lsinitrd
        // see it), creating any missing parent directories.
        if archives.is_empty() {
            archives.push(Vec::new());
        }
        let out = archives.last_mut().unwrap();
        let mut parent = String::new();
        for comp in BLACKLIST_FILE.split('/').collect::<Vec<_>>().split_last().unwrap().1 {
            parent = if parent.is_empty() { comp.to_string() } else { format!("{parent}/{comp}") };
            if !names.contains(&parent) {
                max_ino += 1;
                out.extend(newc_entry(&parent, S_IFDIR | 0o755, 2, max_ino, &[]));
            }
        }
        max_ino += 1;
        out.extend(newc_entry(BLACKLIST_FILE, S_IFREG | 0o644, 1, max_ino, text.as_bytes()));
        stats.log.push(format!("blacklisted in initramfs: {}", mods.join(" ")));
        kept_files += 1;
    }

    if kept_files == 0 {
        return Ok(None);
    }
    // Each archive keeps its own trailer: the kernel resets its hard-link
    // table at a trailer, so merging archives could alias inode numbers.
    let mut out = Vec::with_capacity(data.len());
    for a in archives {
        out.extend_from_slice(&a);
        out.extend(newc_entry(TRAILER, 0, 1, 0, &[]));
        out.resize(out.len().next_multiple_of(512), 0);
    }
    Ok(Some(out))
}

/// Filter a complete initramfs image.
pub fn filter(image: &[u8], filter: &Filter) -> Result<(Vec<u8>, Stats)> {
    let mut stats = Stats::default();
    let mut out = Vec::new();
    let mut off = 0;
    let mut blacklist_added = false;

    while off < image.len() {
        let comp = Compression::detect(&image[off..])?;
        let (segment, next) = if comp == Compression::None {
            // one uncompressed archive (plus its padding)
            let (_, mut end) = parse_archive(image, off)?;
            while end < image.len() && image[end] == 0 {
                end += 1;
            }
            (&image[off..end], end)
        } else {
            // a compressed member runs to the end of the image
            (&image[off..], image.len())
        };

        let (decomp, comp_cmd) = comp.commands();
        let plain = if comp == Compression::None { segment.to_vec() } else { pipe_through(decomp, segment)? };

        // The blacklist goes into the last (main) archive.
        let is_last = next >= image.len();
        match filter_stream(&plain, filter, is_last, &mut stats)? {
            None => {
                stats.dropped_archives += 1;
                stats.log.push(format!("removed {} archive at {off:#x} (nothing left in it)", comp.name()));
            }
            Some(filtered) => {
                blacklist_added |= is_last;
                let bytes = if comp == Compression::None { filtered } else { pipe_through(comp_cmd, &filtered)? };
                stats.log.push(format!(
                    "{} archive at {off:#x}: {} -> {} bytes",
                    comp.name(),
                    segment.len(),
                    bytes.len()
                ));
                out.extend_from_slice(&bytes);
                // Uncompressed archives must start 4-byte aligned; a compressed
                // member is the last one and takes no trailing padding.
                if comp == Compression::None {
                    out.resize(align4(out.len()), 0);
                }
            }
        }
        off = next;
    }
    if !filter.omit_modules.is_empty() && !blacklist_added {
        return Err("initramfs: main archive was emptied, nowhere to put the module blacklist".into());
    }
    Ok((out, stats))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globbing() {
        assert!(glob(b"usr/lib/modules/*/nouveau.ko*", b"usr/lib/modules/6.1/kernel/drivers/gpu/drm/nouveau/nouveau.ko.xz"));
        assert!(!glob(b"usr/lib/modules/*/nouveau.ko*", b"usr/lib/modules/6.1/kernel/x/nouveaux.ko"));
        assert!(Filter::matches(&["usr/lib/firmware/nvidia".into()], "usr/lib/firmware/nvidia/ad102/gsp/x.bin"));
        assert!(!Filter::matches(&["usr/lib/firmware/nvidia".into()], "usr/lib/firmware/nvidia2"));
    }
}
