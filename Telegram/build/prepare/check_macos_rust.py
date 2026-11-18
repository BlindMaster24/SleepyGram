"""Build and load a stripped host proc macro without fetching crates."""

from pathlib import Path
import subprocess
import sys
import tempfile


def check(rustc):
    with tempfile.TemporaryDirectory(prefix='tdesktop-rust-probe-') as directory:
        work = Path(directory)
        macro = work / 'probe.rs'
        library = work / 'libprepare_probe.dylib'
        consumer = work / 'consumer.rs'
        macro.write_text("""
extern crate proc_macro;
use proc_macro::TokenStream;

#[proc_macro_derive(PrepareProbe)]
pub fn probe(_: TokenStream) -> TokenStream {
    "impl Example { const VALUE: u32 = 42; }".parse().unwrap()
}
""")
        consumer.write_text("""
use prepare_probe::PrepareProbe;

#[derive(PrepareProbe)]
pub struct Example;
const _: u32 = Example::VALUE;
""")
        subprocess.run([*rustc, '--version'], cwd=work, check=True)
        subprocess.run([
            *rustc, '--edition=2021', '--crate-name', 'prepare_probe',
            '--crate-type', 'proc-macro', '-C', 'strip=debuginfo',
            macro, '-o', library,
        ], cwd=work, check=True)
        loaded = subprocess.run([
            *rustc, '--edition=2021', '--crate-type', 'lib', consumer,
            '--extern', f'prepare_probe={library}', '--emit=metadata',
        ], cwd=work)
        if loaded.returncode:
            diagnostic = work / 'load.swift'
            diagnostic.write_text("""
import Darwin

if dlopen(CommandLine.arguments[1], RTLD_LAZY | RTLD_LOCAL) == nil {
    print(String(cString: dlerror()))
    exit(1)
}
""")
            subprocess.run([
                'xcrun', '--sdk', 'macosx', 'swift', '-module-cache-path',
                work / 'swift-cache', diagnostic, library,
            ], cwd=work, timeout=60)
            return loaded.returncode
    print('macOS Rust proc-macro probe passed.')
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit('Usage: check_macos_rust.py RUSTC [RUSTC_COMMAND_ARGS...]')
    try:
        sys.exit(check(sys.argv[1:]))
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        sys.exit(f'macOS Rust proc-macro probe failed: {error}')
