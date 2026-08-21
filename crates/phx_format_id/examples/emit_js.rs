//! Emit the browser's copy of the format table.
//!
//!   cargo run -p phx_format_id --example emit_js > crates/phx_format_id/generated/format-id.js
//!
//! The checker cannot call into Rust to ask what a file is: identification has to happen
//! for *every* file, and loading a 189 KB WebAssembly module to compare sixteen bytes would
//! undo the "an ordinary archive downloads no engine" property the probe was built to keep.
//! So the table is generated into JavaScript instead of consulted at runtime, and
//! `generated_file_is_up_to_date` in lib.rs fails the build if the committed output stops
//! matching the table it came from.
//!
//! Only the data is generated; the twenty lines of logic below travel with it, so the file
//! is self-contained and there is still exactly one place either can be edited.

fn main() {
    print!("{}", phx_format_id::emit_javascript());
}
