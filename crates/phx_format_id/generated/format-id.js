// GENERATED — do not edit. Source of truth: crates/phx_format_id/src/lib.rs
// Regenerate: cargo run -p phx_format_id --example emit_js
//
// What a file actually is, decided from its bytes — and, kept separate, what its
// name claims. Those are different statements: a RAR named .zip and a .zip whose
// signature was destroyed both fail a ZIP check, and they need opposite advice.
//
// This is a copy of the table the recovery engine uses, generated from it rather
// than retyped, so the two cannot drift into telling a user different things about
// the same bytes.

/** Two bounded reads decide the whole table: this many bytes from the front… */
export const REQUIRED_PREFIX = 32775;
/** …and this many from the end. Nothing here ever scans, so a 500 GB image costs
*  the same to identify as a 3 KB one. */
export const REQUIRED_SUFFIX = 512;

/** Magic-byte rules, in order. First match wins — the order is the engine's.
 *  Do not sort.
 *
 *  `anchor` is 'start' or 'end'; 'end' means `at` counts backwards from EOF, which is
 *  how a footer is addressed (a fixed VHD, a DMG trailer, a Macrium image).
 *
 *  `provenance` is 'measured' when these bytes were read off a real file, and
 *  'documented' when they come from a specification or a reader implementation and
 *  were NOT verified here. Show the difference; do not average it away. */
export const SIGNATURES = [
  { format: 'zip', anchor: 'start', at: 0, minLen: 4, magic: [0x50, 0x4b, 0x03], provenance: 'measured', source: 'the project\'s own ZIP corpus (2268 files)', caveat: null },
  { format: 'zip', anchor: 'start', at: 0, minLen: 4, magic: [0x50, 0x4b, 0x05], provenance: 'measured', source: 'the project\'s own ZIP corpus (2268 files)', caveat: null },
  { format: 'zip', anchor: 'start', at: 0, minLen: 4, magic: [0x50, 0x4b, 0x07], provenance: 'measured', source: 'the project\'s own ZIP corpus (2268 files)', caveat: null },
  { format: 'gzip', anchor: 'start', at: 0, minLen: 2, magic: [0x1f, 0x8b], provenance: 'measured', source: 'engine corpus, gzip members', caveat: null },
  { format: 'sqlite', anchor: 'start', at: 0, minLen: 16, magic: [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00], provenance: 'measured', source: 'engine corpus, sqlite databases', caveat: null },
  { format: 'pdf', anchor: 'start', at: 0, minLen: 5, magic: [0x25, 0x50, 0x44, 0x46, 0x2d], provenance: 'measured', source: 'engine corpus, pdf documents', caveat: null },
  { format: 'bzip2', anchor: 'start', at: 0, minLen: 3, magic: [0x42, 0x5a, 0x68], provenance: 'measured', source: 'engine corpus, bzip2 streams', caveat: null },
  { format: 'xz', anchor: 'start', at: 0, minLen: 6, magic: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], provenance: 'measured', source: 'engine corpus, xz streams', caveat: null },
  { format: 'zstd', anchor: 'start', at: 0, minLen: 4, magic: [0x28, 0xb5, 0x2f, 0xfd], provenance: 'measured', source: 'engine corpus, zstd streams', caveat: null },
  { format: 'lz4', anchor: 'start', at: 0, minLen: 4, magic: [0x04, 0x22, 0x4d, 0x18], provenance: 'measured', source: 'engine corpus, lz4 streams', caveat: null },
  { format: '7z', anchor: 'start', at: 0, minLen: 6, magic: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], provenance: 'measured', source: 'engine corpus, 7-Zip archives', caveat: null },
  { format: 'rar', anchor: 'start', at: 0, minLen: 7, magic: [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], provenance: 'measured', source: 'engine corpus, RAR archives', caveat: null },
  { format: 'cab', anchor: 'start', at: 0, minLen: 4, magic: [0x4d, 0x53, 0x43, 0x46], provenance: 'measured', source: 'C:\\Windows\\Logs\\CBS\\CbsPersist_*.cab', caveat: null },
  { format: 'wim', anchor: 'start', at: 0, minLen: 8, magic: [0x4d, 0x53, 0x57, 0x49, 0x4d, 0x00, 0x00, 0x00], provenance: 'measured', source: 'C:\\Windows\\System32\\DrtmAuthTxt.wim', caveat: null },
  { format: 'qcow2', anchor: 'start', at: 0, minLen: 4, magic: [0x51, 0x46, 0x49, 0xfb], provenance: 'measured', source: '~/.android/avd/*.avd/cache.img.qcow2', caveat: null },
  { format: 'vhdx', anchor: 'start', at: 0, minLen: 8, magic: [0x76, 0x68, 0x64, 0x78, 0x66, 0x69, 0x6c, 0x65], provenance: 'documented', source: 'Microsoft [MS-VHDX] §2.1 File Type Identifier; matches libyal/libvhdi and qemu block/vhdx.h', caveat: null },
  { format: 'vhd', anchor: 'start', at: 0, minLen: 512, magic: [0x63, 0x6f, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x78], provenance: 'documented', source: 'Microsoft Virtual Hard Disk Image Format Specification — footer copy at the head of dynamic/differencing disks', caveat: 'fixed-size VHDs have no header copy; they match the End(512) rule below' },
  { format: 'vmdk', anchor: 'start', at: 0, minLen: 512, magic: [0x4b, 0x44, 0x4d, 0x56], provenance: 'documented', source: 'VMware sparse extent header magic 0x564D444B; matches libyal/libvmdk and qemu block/vmdk.c', caveat: 'monolithic-flat VMDKs are a plain-text descriptor plus a raw extent and carry no magic' },
  { format: 'acronis_tib', anchor: 'start', at: 0, minLen: 8, magic: [0xce, 0x24, 0xb9, 0xa2, 0x20, 0x00, 0x00, 0x00], provenance: 'documented', source: 'file(1) magic database submission, 2018-11 (Magdir/archive)', caveat: 'author verified True Image 2013 and 2019 only; older builds use a different stamp, and TIBX is a separate format' },
  { format: 'vhd', anchor: 'end', at: 512, minLen: 512, magic: [0x63, 0x6f, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x78], provenance: 'documented', source: 'Microsoft Virtual Hard Disk Image Format Specification — the 512-byte footer every VHD ends with', caveat: null },
  { format: 'dmg', anchor: 'end', at: 512, minLen: 512, magic: [0x6b, 0x6f, 0x6c, 0x79], provenance: 'documented', source: 'UDIF trailer, 0x6B6F6C79; matches libyal/libmodi and qemu block/dmg.c', caveat: 'qemu searches a small window rather than a fixed offset, so an image with padding after the trailer will not match this rule' },
  { format: 'macrium_x', anchor: 'end', at: 12, minLen: 20, magic: [0x4d, 0x41, 0x43, 0x52, 0x49, 0x55, 0x4d, 0x5f, 0x46, 0x49, 0x4c, 0x45], provenance: 'documented', source: 'macrium/mrimgx_file_layout, docs/FILE_LAYOUT.md: struct Footer { uint64 first_metadata_block_header; uint8 magic_bytes[12]; }', caveat: 'Reflect X (.mrimgx/.mrbakx) only; the legacy .mrimg format has no dependable signature' },
  { format: 'tar', anchor: 'start', at: 257, minLen: 263, magic: [0x75, 0x73, 0x74, 0x61, 0x72], provenance: 'measured', source: 'engine corpus, tar archives', caveat: null },
  { format: 'iso9660', anchor: 'start', at: 32769, minLen: 32775, magic: [0x43, 0x44, 0x30, 0x30, 0x31], provenance: 'measured', source: 'engine corpus, ISO 9660 images', caveat: null },
];

/** Everything else worth saying about a format, keyed by its identifier. */
export const FORMATS = {
  zip: { label: 'ZIP archive', multiMember: true, extensions: ['.zip', '.jar', '.apk', '.docx', '.xlsx', '.pptx', '.epub', '.odt', '.ods'] },
  tar: { label: 'TAR archive', multiMember: true, extensions: ['.tar'] },
  iso9660: { label: 'ISO 9660 disc image', multiMember: true, extensions: ['.iso'] },
  gzip: { label: 'gzip stream', multiMember: false, extensions: ['.gz', '.tgz'] },
  sqlite: { label: 'SQLite database', multiMember: false, extensions: ['.db', '.sqlite', '.sqlite3'] },
  '7z': { label: '7-Zip archive', multiMember: true, extensions: ['.7z'] },
  rar: { label: 'RAR archive', multiMember: true, extensions: ['.rar'] },
  pdf: { label: 'PDF document', multiMember: false, extensions: ['.pdf'] },
  bzip2: { label: 'bzip2 stream', multiMember: false, extensions: ['.bz2'] },
  xz: { label: 'xz stream', multiMember: false, extensions: ['.xz'] },
  zstd: { label: 'Zstandard stream', multiMember: false, extensions: ['.zst', '.zstd'] },
  lz4: { label: 'LZ4 stream', multiMember: false, extensions: ['.lz4'] },
  cab: { label: 'Microsoft Cabinet archive', multiMember: true, extensions: ['.cab'] },
  wim: { label: 'Windows image (WIM)', multiMember: true, extensions: ['.wim'] },
  qcow2: { label: 'QCOW2 disk image', multiMember: false, extensions: ['.qcow2', '.qcow'] },
  vhd: { label: 'VHD virtual disk', multiMember: false, extensions: ['.vhd'] },
  vhdx: { label: 'VHDX virtual disk', multiMember: false, extensions: ['.vhdx', '.avhdx'] },
  vmdk: { label: 'VMDK virtual disk', multiMember: false, extensions: ['.vmdk'] },
  dmg: { label: 'Apple disk image (DMG)', multiMember: false, extensions: ['.dmg'] },
  acronis_tib: { label: 'Acronis True Image backup', multiMember: false, extensions: ['.tib'] },
  macrium_x: { label: 'Macrium Reflect X image', multiMember: false, extensions: ['.mrimgx', '.mrbakx'] },
};

/**
 * The bytes a rule is tested against: a bounded head, a bounded tail, and how long the file
 * really is. `totalLen` is required and not derived — an end-anchored rule is a statement
 * about a position relative to the end of the FILE, so a tail handed over without saying
 * what it is the tail of would only produce a guess.
 */
export function bytesOf(head, tail, totalLen) {
  return { head, tail, totalLen };
}

/** For a file small enough to hold entirely, where head and tail are the same array. */
export function whole(all) {
  return { head: all, tail: all, totalLen: all.length };
}

function windowFor(b, s) {
  if (s.anchor === 'start') {
    if (s.at + s.magic.length > b.head.length) return null;
    return { buf: b.head, at: s.at };
  }
  // 'end': `at` counts backwards from EOF. Bail rather than wrap when the tail we were
  // given is shorter than the rule needs.
  if (s.at > b.totalLen || s.at > b.tail.length) return null;
  const at = b.tail.length - s.at;
  if (at + s.magic.length > b.tail.length) return null;
  return { buf: b.tail, at };
}

/** What the bytes say, with how the signature came to be believed. `null` when nothing matched. */
export function identifyDetailed(b) {
  for (const s of SIGNATURES) {
    if (b.totalLen < s.minLen) continue;
    const w = windowFor(b, s);
    if (!w) continue;
    let hit = true;
    for (let i = 0; i < s.magic.length; i++) {
      if (w.buf[w.at + i] !== s.magic[i]) { hit = false; break; }
    }
    if (hit) return { format: s.format, provenance: s.provenance, source: s.source, caveat: s.caveat };
  }
  return null;
}

/** What the bytes say. `null` when nothing matched — a real answer, not a failure. */
export function identify(b) {
  const found = identifyDetailed(b);
  return found && found.format;
}

/** What the name claims. The longest matching extension wins, so `.sqlite3` is not `.sqlite`. */
export function fromExtension(name) {
  const lower = String(name || '').toLowerCase();
  let best = null;
  for (const [id, meta] of Object.entries(FORMATS)) {
    for (const ext of meta.extensions) {
      if (lower.endsWith(ext) && (best === null || ext.length > best.len)) best = { len: ext.length, id };
    }
  }
  return best && best.id;
}

/**
 * Both answers, kept apart, plus how they relate:
 *
 *   match        both say the same thing
 *   mismatch     both spoke and disagree — renamed, or the wrong extension. Content wins.
 *   content-only the bytes identify it; the name says nothing
 *   name-only    the name claims a format the bytes do not confirm — usually a damaged
 *                signature, and the most useful thing there is to be able to say
 *   unknown      neither identifies anything
 */
export function identification(b, name) {
  const found = identifyDetailed(b);
  const byContent = found && found.format;
  const byName = fromExtension(name);
  let agreement;
  if (byContent && byName) agreement = byContent === byName ? 'match' : 'mismatch';
  else if (byContent) agreement = 'content-only';
  else if (byName) agreement = 'name-only';
  else agreement = 'unknown';
  return {
    byContent,
    byName,
    agreement,
    bestEffort: byContent || byName || null,
    // How the content answer was reached. A tool showing this to a person must not present
    // 'documented' as though it were 'measured'.
    provenance: found ? found.provenance : null,
    source: found ? found.source : null,
    caveat: found ? found.caveat : null,
  };
}
