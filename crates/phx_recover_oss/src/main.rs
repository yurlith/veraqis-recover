//! `phx-recover-oss` — open-core structural archive recovery.
//!
//! The open half of the PHX/VERAQIS recovery engine: base structural repair
//! for ZIP/gzip/tar (central-directory reconstruction, CRC fixes, member
//! resync), independently CRC/SHA-verified against the surviving bytes. This
//! binary links only the open crates — `phx_format_id`, `phx_zip_core`,
//! `phx_analyze_engine`, and `phx_recovery` built with `default-features =
//! false` — so it cannot see `phx_verify_cert` (proof-carrying certificates),
//! Tier-3 semantic recovery, or any licensing/tier logic. One mode, always
//! free, always local. See `OPEN_CORE_STRATEGY.md` §4 for the exact boundary
//! and why it's drawn there.
//!
//! This tool never invents bytes: a region is reported recovered only when
//! surviving structure proves it (the same `false_recovered_bytes = 0`
//! invariant the rest of the engine gates on). Unrecoverable input abstains —
//! it is never guessed at.

use std::path::PathBuf;

use clap::Parser;
use phx_analyze_engine::model::AnalysisConfig;
use phx_analyze_engine::Engine;
use phx_recovery::{RecoveryEngine, RecoveryOptions};

/// Success, no issues detected (or successfully recovered).
const EXIT_SUCCESS: i32 = 0;
/// Damage found and not (fully) recovered.
const EXIT_ISSUES: i32 = 1;
/// Fatal error (I/O, unreadable input, unwritable output).
const EXIT_FATAL: i32 = 2;

/// Open structural recovery for damaged ZIP, gzip, and tar archives.
///
/// Analyzes `PATH` read-only, reports what structural damage was found, and
/// — if `--output` is given — attempts recovery, writing only bytes an
/// independent checksum proves. Never modifies the source.
#[derive(Debug, Parser)]
#[command(name = "phx-recover-oss", version, about)]
struct Cli {
    /// Damaged archive to analyze (read-only; never modified).
    path: PathBuf,
    /// Directory to write recovered output into. Omitted: analyze only, write
    /// nothing (dry run).
    #[arg(long)]
    output: Option<PathBuf>,
}

fn main() {
    std::process::exit(run(&Cli::parse()));
}

/// Exit code as a plain `i32`, not [`std::process::ExitCode`] — `ExitCode` is
/// deliberately opaque (no `PartialEq`) and can't be asserted on in a test, so
/// the testable logic lives here and `main` converts at the process boundary.
fn run(cli: &Cli) -> i32 {
    let analysis = match Engine::new().analyze(&cli.path, AnalysisConfig::default()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("phx-recover-oss: analysis failed: {e}");
            return EXIT_FATAL;
        }
    };

    println!(
        "phx-recover-oss: {} — {}",
        cli.path.display(),
        if analysis.is_clean() {
            "no structural damage detected"
        } else {
            "structural damage detected"
        }
    );
    for c in &analysis.corruptions {
        println!("  - {} ({:?})", c.chain.primary.rule_id, c.severity);
    }

    let Some(output_dir) = cli.output.clone() else {
        println!("phx-recover-oss: pass --output <dir> to attempt recovery.");
        return if analysis.is_clean() {
            EXIT_SUCCESS
        } else {
            EXIT_ISSUES
        };
    };

    if let Err(e) = std::fs::create_dir_all(&output_dir) {
        eprintln!("phx-recover-oss: cannot create output directory: {e}");
        return EXIT_FATAL;
    }

    let options = RecoveryOptions {
        output_dir,
        hash_type: analysis.integrity_result.hash_type,
        ..Default::default()
    };

    match RecoveryEngine::new().recover(&cli.path, &analysis, &options) {
        Ok(report) => {
            println!(
                "phx-recover-oss: {} — {} byte(s) verified-recovered, {} byte(s) lost \
                 (unproven bytes are never emitted: false_recovered_bytes = 0)",
                if report.success {
                    "recovery succeeded"
                } else {
                    "nothing recoverable — abstained"
                },
                report.bytes_recovered,
                report.bytes_lost,
            );
            for w in &report.warnings {
                println!("  note: {w}");
            }
            if analysis.is_clean() || report.success {
                EXIT_SUCCESS
            } else {
                EXIT_ISSUES
            }
        }
        Err(e) => {
            eprintln!("phx-recover-oss: recovery failed: {e}");
            EXIT_FATAL
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phx_test_utils::generators::{zip_local_header_only, zip_without_eocd};

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "phx-recover-oss-test-{}-{name}",
            std::process::id()
        ))
    }

    /// Golden path: a ZIP with a local file header + data but no central
    /// directory (`zip_local_header_only` — the documented case
    /// `ZipCentralDirectoryRebuild` repairs) recovers byte-exact.
    #[test]
    fn golden_path_recovers_a_damaged_zip() {
        let dir = temp_dir("golden");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("damaged.zip");
        std::fs::write(&input, zip_local_header_only("hello.txt", b"hello world"))
            .expect("write fixture");

        let output_dir = dir.join("out");
        let cli = Cli {
            path: input,
            output: Some(output_dir),
        };
        let code = run(&cli);

        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(code, EXIT_SUCCESS, "a repairable ZIP must recover cleanly");
    }

    /// Refusal path: a ZIP-looking blob with no EOCD and no valid local
    /// header is a structural catastrophe — nothing here proves a rebuild, so
    /// the engine must abstain, never guess. Verified two ways: the exit code
    /// carries "issues" (not success), and no output file was written.
    #[test]
    fn unrecoverable_input_abstains_never_guesses() {
        let dir = temp_dir("abstain");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("garbage.zip");
        std::fs::write(&input, zip_without_eocd()).expect("write fixture");

        let output_dir = dir.join("out");
        let cli = Cli {
            path: input,
            output: Some(output_dir.clone()),
        };
        let code = run(&cli);

        let recovered_something = output_dir
            .read_dir()
            .map(|mut it| it.next().is_some())
            .unwrap_or(false);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(
            code, EXIT_ISSUES,
            "an unrecoverable input must not report success"
        );
        assert!(
            !recovered_something,
            "abstaining must write nothing, never a guess"
        );
    }
}
