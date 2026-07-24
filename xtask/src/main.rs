use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const REQUIRED_SYS_SOURCES: &[&str] = &[
    "CMakeLists.txt",
    "build.rs",
    "build/platform/android.rs",
    "build/platform/ios.rs",
    "build/platform/linux.rs",
    "build/platform/macos.rs",
    "build/platform/mod.rs",
    "build/platform/ohos.rs",
    "build/platform/unix.rs",
    "build/platform/windows.rs",
    "src/bridge.cpp",
    "src/lib.rs",
    "src/wrapper.h",
    "patches/asio.patch",
    "patches/openvpn3.patch",
    "vendor/asio/asio/include/asio.hpp",
    "vendor/asio/asio/LICENSE_1_0.txt",
    "vendor/openvpn3/client/ovpncli.cpp",
    "vendor/openvpn3/client/ovpncli.hpp",
    "vendor/openvpn3/LICENSE.md",
];
const SUBMODULES: &[(&str, &str)] = &[
    (
        "openvpn-connect-sys/vendor/openvpn3",
        "18edfae7e7fd8051c93bd4746ec69be91eb02dbb",
    ),
    (
        "openvpn-connect-sys/vendor/asio",
        "147f7225a96d45a2807a64e443177f621844e51c",
    ),
];

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args().skip(1);
    match arguments.next().as_deref() {
        Some("package") => package(arguments),
        Some("--help" | "-h") | None => {
            print_help();
            Ok(())
        }
        Some(command) => Err(format!("unknown command: {command}")),
    }
}

fn package(arguments: impl Iterator<Item = String>) -> Result<(), String> {
    let mut allow_dirty = false;
    let mut no_verify = false;
    for argument in arguments {
        match argument.as_str() {
            "--allow-dirty" => allow_dirty = true,
            "--no-verify" => no_verify = true,
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            _ => return Err(format!("unknown package option: {argument}")),
        }
    }

    let workspace = workspace_root()?;
    verify_submodules(&workspace)?;
    cargo_package(&workspace, "openvpn-connect-sys", allow_dirty, no_verify)?;
    audit_sys_archive(&workspace)?;

    list_upper_crate(&workspace, allow_dirty)?;
    println!(
        "sys source package is ready under target/package; publish it before packaging openvpn-connect"
    );
    Ok(())
}

fn verify_submodules(workspace: &Path) -> Result<(), String> {
    for (relative, expected) in SUBMODULES {
        let path = workspace.join(relative);
        let output = Command::new("git")
            .arg("-C")
            .arg(&path)
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|error| format!("failed to inspect submodule {relative}: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "submodule {relative} is missing; run `git submodule update --init --recursive`"
            ));
        }
        let actual = String::from_utf8_lossy(&output.stdout);
        if actual.trim() != *expected {
            return Err(format!(
                "submodule {relative} is at {}, expected {expected}",
                actual.trim()
            ));
        }
    }
    println!("submodule revisions match the audited native source set");
    Ok(())
}

fn list_upper_crate(workspace: &Path, allow_dirty: bool) -> Result<(), String> {
    println!("checking openvpn-connect publish file list");
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace)
        .arg("package")
        .arg("--package")
        .arg("openvpn-connect")
        .arg("--list");
    if allow_dirty {
        command.arg("--allow-dirty");
    }
    let status = command
        .status()
        .map_err(|error| format!("failed to inspect openvpn-connect package: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err("could not produce the openvpn-connect package file list".to_owned())
    }
}

fn cargo_package(
    workspace: &Path,
    package: &str,
    allow_dirty: bool,
    no_verify: bool,
) -> Result<(), String> {
    println!("packaging {package}");
    let mut command = Command::new("cargo");
    command
        .current_dir(workspace)
        .arg("package")
        .arg("--package")
        .arg(package);
    if allow_dirty {
        command.arg("--allow-dirty");
    }
    if no_verify {
        command.arg("--no-verify");
    }
    let status = command
        .status()
        .map_err(|error| format!("failed to start cargo package: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("cargo package failed for {package}"))
    }
}

fn audit_sys_archive(workspace: &Path) -> Result<(), String> {
    let workspace_version = workspace_version(workspace)?;
    let archive = workspace
        .join("target/package")
        .join(format!("openvpn-connect-sys-{workspace_version}.crate"));
    let output = Command::new("tar")
        .arg("-tzf")
        .arg(&archive)
        .output()
        .map_err(|error| format!("failed to inspect {}: {error}", archive.display()))?;
    if !output.status.success() {
        return Err(format!(
            "could not read source archive {}",
            archive.display()
        ));
    }
    let listing = String::from_utf8(output.stdout)
        .map_err(|error| format!("archive listing was not UTF-8: {error}"))?;
    let prefix = format!("openvpn-connect-sys-{workspace_version}/");

    for source in REQUIRED_SYS_SOURCES {
        let expected = format!("{prefix}{source}");
        if !listing.lines().any(|entry| entry == expected) {
            return Err(format!("source package is missing {source}"));
        }
    }
    for entry in listing.lines() {
        let lower = entry.to_ascii_lowercase();
        if lower.contains("/prebuilt/")
            || [".a", ".so", ".dylib", ".dll", ".lib"]
                .iter()
                .any(|extension| lower.ends_with(extension))
        {
            return Err(format!("source package contains native artifact: {entry}"));
        }
    }
    println!(
        "audited {}: complete OpenVPN/Asio source, no native binaries",
        archive.display()
    );
    Ok(())
}

fn workspace_root() -> Result<PathBuf, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| "xtask is not inside the workspace".to_owned())
}

fn workspace_version(workspace: &Path) -> Result<String, String> {
    let manifest = std::fs::read_to_string(workspace.join("Cargo.toml"))
        .map_err(|error| format!("failed to read workspace Cargo.toml: {error}"))?;
    manifest
        .lines()
        .skip_while(|line| line.trim() != "[workspace.package]")
        .skip(1)
        .take_while(|line| !line.trim().starts_with('['))
        .find_map(|line| {
            line.trim()
                .strip_prefix("version = ")
                .map(|value| value.trim_matches('"').to_owned())
        })
        .ok_or_else(|| "workspace package version is missing".to_owned())
}

fn print_help() {
    println!(
        "\
Build and audit the publishable sys source crate.

Usage: cargo xtask package [options]

Options:
  --allow-dirty   Allow packaging a modified worktree
  --no-verify     Skip Cargo's isolated sys-crate build verification

The audit requires OpenVPN Core and Asio source files and rejects prebuilt
native libraries in the openvpn-connect-sys archive. It also requires the
audited submodule commits. Publish sys first; Cargo can package openvpn-connect
after that exact sys version reaches the registry."
    );
}
