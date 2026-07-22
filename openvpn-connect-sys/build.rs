use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const OPENVPN3_PATCH: &str = include_str!("patches/openvpn3.patch");
const ASIO_PATCH: &str = include_str!("patches/asio.patch");
const OHOS_SDK_NATIVE_ENV: &str = "OHOS_SDK_NATIVE";

const PREFIX_ENV_VARS: &[(&str, &str)] = &[
    ("OPENVPN3_ASIO_DIR", "asio.hpp"),
    ("OPENVPN3_LZ4_DIR", "lz4.h"),
    ("OPENVPN3_OPENSSL_DIR", "openssl/ssl.h"),
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinkMode {
    Static,
    Dynamic,
}

#[derive(Clone, Copy)]
struct NativeFeatures {
    dco: bool,
    external_transport: bool,
    external_tun: bool,
}

#[derive(Clone, Copy)]
struct BuildTarget<'a> {
    triple: &'a str,
    os: &'a str,
    env: &'a str,
    arch: &'a str,
}

impl LinkMode {
    fn detect() -> Self {
        if env::var_os("CARGO_FEATURE_VENDOR").is_some() {
            Self::Static
        } else {
            Self::Dynamic
        }
    }

    const fn cmake_type(self) -> &'static str {
        match self {
            Self::Static => "STATIC",
            Self::Dynamic => "SHARED",
        }
    }

    const fn cargo_kind(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Dynamic => "dylib",
        }
    }
}

fn main() {
    emit_rerun_rules();
    generate_bindings();
    let sources = prepare_native_sources();

    let target = env::var("TARGET").expect("Cargo must set TARGET");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo must set target OS");
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo must set target arch");
    let mode = LinkMode::detect();
    let native_features = NativeFeatures {
        dco: env::var_os("CARGO_FEATURE_DCO").is_some(),
        external_transport: env::var_os("CARGO_FEATURE_EXTERNAL_TRANSPORT").is_some(),
        external_tun: env::var_os("CARGO_FEATURE_EXTERNAL_TUN").is_some(),
    };

    let dependencies =
        DependencyPaths::discover(&target_os, is_host_build(), mode, &sources.asio_include);
    let native = compile_openvpn(
        BuildTarget {
            triple: &target,
            os: &target_os,
            env: &target_env,
            arch: &target_arch,
        },
        mode,
        native_features,
        &dependencies,
        &sources.openvpn3,
    );
    emit_discovered_dependency_paths(&dependencies);
    emit_native_link(&native, &target_os, &target_env, mode);
}

fn emit_rerun_rules() {
    for path in [
        "CMakeLists.txt",
        "src/wrapper.h",
        "src/bridge.cpp",
        "patches/openvpn3.patch",
        "patches/asio.patch",
        "vendor/asio/asio/include",
        "vendor/openvpn3/client",
        "vendor/openvpn3/openvpn",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    for (variable, _) in PREFIX_ENV_VARS {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    for variable in [
        "OHOS_NDK_HOME",
        OHOS_SDK_NATIVE_ENV,
        "ANDROID_NDK_HOME",
        "ANDROID_NDK_ROOT",
        "NDK_HOME",
        "DEP_LZ4_INCLUDE",
        "DEP_LZ4_ROOT",
        "DEP_OPENSSL_INCLUDE",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
}

struct NativeSources {
    openvpn3: PathBuf,
    asio_include: PathBuf,
}

fn prepare_native_sources() -> NativeSources {
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("Cargo must set CARGO_MANIFEST_DIR"),
    );
    let upstream_openvpn3 = manifest.join("vendor/openvpn3");
    let upstream_asio = manifest.join("vendor/asio/asio/include");
    require_submodule_source(
        &upstream_openvpn3.join("client/ovpncli.cpp"),
        "vendor/openvpn3",
    );
    require_submodule_source(&upstream_asio.join("asio.hpp"), "vendor/asio");

    let staging = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR"))
        .join("patched-native-source");
    if staging.exists() {
        fs::remove_dir_all(&staging)
            .unwrap_or_else(|error| panic!("failed to reset {}: {error}", staging.display()));
    }

    let openvpn3 = staging.join("openvpn3");
    copy_tree(&upstream_openvpn3.join("client"), &openvpn3.join("client"));
    copy_tree(
        &upstream_openvpn3.join("openvpn"),
        &openvpn3.join("openvpn"),
    );
    apply_unified_patch(&openvpn3, OPENVPN3_PATCH);

    let asio = staging.join("asio");
    let asio_include = asio.join("asio/include");
    copy_tree(&upstream_asio, &asio_include);
    apply_unified_patch(&asio, ASIO_PATCH);

    NativeSources {
        openvpn3,
        asio_include,
    }
}

fn require_submodule_source(path: &Path, submodule: &str) {
    assert!(
        path.is_file(),
        "missing {submodule}; initialize sources with `git submodule update --init --recursive` before building"
    );
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", destination.display()));
    let entries = fs::read_dir(source)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", source.display()));
    for entry in entries {
        let entry = entry.expect("failed to read native source entry");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .expect("failed to read native source file type");
        if file_type.is_dir() {
            copy_tree(&source_path, &destination_path);
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path).unwrap_or_else(|error| {
                panic!(
                    "failed to copy {} to {}: {error}",
                    source_path.display(),
                    destination_path.display()
                )
            });
        } else {
            panic!("unsupported native source entry: {}", source_path.display());
        }
    }
}

fn apply_unified_patch(root: &Path, patch: &str) {
    for section in patch.split("diff --git ").filter(|value| !value.is_empty()) {
        apply_file_patch(root, section);
    }
}

fn apply_file_patch(root: &Path, section: &str) {
    let lines: Vec<&str> = section.lines().collect();
    let relative = lines
        .iter()
        .find_map(|line| line.strip_prefix("+++ b/"))
        .expect("patch section has no destination path");
    let path = root.join(relative);
    let source = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read patch target {}: {error}", path.display()));
    let had_final_newline = source.ends_with('\n');
    let original: Vec<&str> = source.lines().collect();
    let mut output = Vec::with_capacity(original.len());
    let mut cursor = 0;
    let mut index = 0;

    while index < lines.len() {
        let Some(header) = lines[index].strip_prefix("@@ ") else {
            index += 1;
            continue;
        };
        let start = old_hunk_start(header);
        let hunk_cursor = start.saturating_sub(1);
        assert!(
            hunk_cursor >= cursor && hunk_cursor <= original.len(),
            "invalid hunk position for {}",
            path.display()
        );
        output.extend(
            original[cursor..hunk_cursor]
                .iter()
                .map(ToString::to_string),
        );
        cursor = hunk_cursor;
        index += 1;

        while index < lines.len() && !lines[index].starts_with("@@ ") {
            let line = lines[index];
            if line == "\\ No newline at end of file" {
                index += 1;
                continue;
            }
            let (marker, text) = line.split_at(1);
            match marker {
                " " => {
                    verify_patch_line(&path, &original, cursor, text);
                    output.push(text.to_owned());
                    cursor += 1;
                }
                "-" => {
                    verify_patch_line(&path, &original, cursor, text);
                    cursor += 1;
                }
                "+" => output.push(text.to_owned()),
                _ => break,
            }
            index += 1;
        }
    }

    output.extend(original[cursor..].iter().map(ToString::to_string));
    let mut patched = output.join("\n");
    if had_final_newline {
        patched.push('\n');
    }
    fs::write(&path, patched)
        .unwrap_or_else(|error| panic!("failed to write patch target {}: {error}", path.display()));
}

fn old_hunk_start(header: &str) -> usize {
    header
        .split_whitespace()
        .next()
        .and_then(|range| range.strip_prefix('-'))
        .and_then(|range| range.split(',').next())
        .and_then(|start| start.parse().ok())
        .expect("invalid unified patch hunk header")
}

fn verify_patch_line(path: &Path, original: &[&str], cursor: usize, expected: &str) {
    let actual = original.get(cursor).unwrap_or_else(|| {
        panic!(
            "patch for {} extends beyond the source at line {}",
            path.display(),
            cursor + 1
        )
    });
    assert_eq!(
        *actual,
        expected,
        "source drift while applying patch to {} at line {}",
        path.display(),
        cursor + 1
    );
}

fn generate_bindings() {
    let bindings = bindgen::Builder::default()
        .header("src/wrapper.h")
        .allowlist_function("ovpn_.*")
        .allowlist_type("ovpn_.*")
        .derive_default(true)
        .generate_comments(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("failed to generate OpenVPN C ABI bindings; is libclang installed?");

    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR"));
    bindings
        .write_to_file(out.join("bindings.rs"))
        .expect("failed to write generated OpenVPN bindings");
}

#[derive(Debug)]
struct NativeLibrary {
    lib_dir: PathBuf,
    runtime_dir: Option<PathBuf>,
    _library_file: PathBuf,
}

fn library_filename(target_os: &str, target_env: &str, mode: LinkMode) -> &'static str {
    match (target_os, target_env, mode) {
        ("windows", "msvc", _) => "openvpn3_core.lib",
        ("windows", _, LinkMode::Dynamic) => "libopenvpn3_core.dll.a",
        (_, _, LinkMode::Static) => "libopenvpn3_core.a",
        ("macos" | "ios", _, LinkMode::Dynamic) => "libopenvpn3_core.dylib",
        (_, _, LinkMode::Dynamic) => "libopenvpn3_core.so",
    }
}

#[derive(Debug)]
struct DependencyPaths {
    asio_include: PathBuf,
    lz4_include: PathBuf,
    lz4_lib: Option<PathBuf>,
    openssl_include: PathBuf,
    openssl_lib: Option<PathBuf>,
}

impl DependencyPaths {
    fn discover(
        target_os: &str,
        host_build: bool,
        mode: LinkMode,
        patched_asio_include: &Path,
    ) -> Self {
        if mode == LinkMode::Static {
            return Self::vendored(patched_asio_include);
        }

        let asio_include = dependency_prefix_override("OPENVPN3_ASIO_DIR", "asio.hpp").map_or_else(
            || patched_asio_include.to_path_buf(),
            |prefix| prefix.join("include"),
        );
        let lz4 = dependency_prefix(
            "OPENVPN3_LZ4_DIR",
            "lz4.h",
            target_os,
            host_build,
            &["lz4", "lz4"],
        );
        let openssl = dependency_prefix(
            "OPENVPN3_OPENSSL_DIR",
            "openssl/ssl.h",
            target_os,
            host_build,
            &["openssl@3", "openssl"],
        );

        Self {
            asio_include: absolute(asio_include),
            lz4_include: absolute(lz4.join("include")),
            lz4_lib: library_dir(&lz4).map(absolute),
            openssl_include: absolute(openssl.join("include")),
            openssl_lib: library_dir(&openssl).map(absolute),
        }
    }

    fn vendored(patched_asio_include: &Path) -> Self {
        let lz4_include = cargo_metadata_path("DEP_LZ4_INCLUDE", "lz4-sys");
        let lz4_root = cargo_metadata_path("DEP_LZ4_ROOT", "lz4-sys");
        let openssl_include = cargo_metadata_path("DEP_OPENSSL_INCLUDE", "openssl-sys");
        let openssl_prefix = openssl_include
            .parent()
            .expect("DEP_OPENSSL_INCLUDE has no parent directory")
            .to_path_buf();

        Self {
            asio_include: absolute(patched_asio_include.to_path_buf()),
            lz4_include: absolute(lz4_include),
            lz4_lib: library_dir_or_root(&lz4_root).map(absolute),
            openssl_include: absolute(openssl_include),
            openssl_lib: library_dir(&openssl_prefix).map(absolute),
        }
    }
}

fn dependency_prefix_override(env_var: &str, header: &str) -> Option<PathBuf> {
    let prefix = PathBuf::from(env::var_os(env_var)?);
    assert_header(&prefix, header, env_var);
    Some(prefix)
}

fn cargo_metadata_path(variable: &str, dependency: &str) -> PathBuf {
    env::var_os(variable).map_or_else(
        || {
            panic!(
                "Cargo did not provide {variable} from {dependency}; the `vendor` feature requires its source-built native metadata"
            )
        },
        PathBuf::from,
    )
}

fn dependency_prefix(
    env_var: &str,
    header: &str,
    target_os: &str,
    host_build: bool,
    mac_formulae: &[&str],
) -> PathBuf {
    if let Some(prefix) = dependency_prefix_override(env_var, header) {
        return prefix;
    }

    if host_build && (target_os == "macos" || target_os == "ios") {
        for homebrew_root in ["/opt/homebrew/opt", "/usr/local/opt"] {
            for formula in mac_formulae {
                let prefix = Path::new(homebrew_root).join(formula);
                if prefix.join("include").join(header).is_file() {
                    return prefix;
                }
            }
        }
    }

    if host_build {
        let system = PathBuf::from("/usr");
        if system.join("include").join(header).is_file() {
            return system;
        }
    }

    panic!(
        "could not find {header} for {target_os}; install its development package, set {env_var} to the target dependency prefix, or enable the `vendor` feature"
    );
}

fn assert_header(prefix: &Path, header: &str, env_var: &str) {
    assert!(
        prefix.join("include").join(header).is_file(),
        "{env_var}={} does not contain include/{header}",
        prefix.display()
    );
}

fn library_dir(prefix: &Path) -> Option<PathBuf> {
    [prefix.join("lib"), prefix.join("lib64")]
        .into_iter()
        .find(|path| path.is_dir())
}

fn library_dir_or_root(prefix: &Path) -> Option<PathBuf> {
    library_dir(prefix).or_else(|| prefix.is_dir().then(|| prefix.to_path_buf()))
}

fn absolute(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        env::current_dir()
            .expect("failed to read current directory")
            .join(path)
    }
}

fn compile_openvpn(
    target: BuildTarget<'_>,
    mode: LinkMode,
    features: NativeFeatures,
    dependencies: &DependencyPaths,
    openvpn3_source: &Path,
) -> NativeLibrary {
    let mut config = cmake::Config::new(".");
    config
        .define("OPENVPN_CONNECT_LIBRARY_TYPE", mode.cmake_type())
        .define("OPENVPN_CONNECT_OPENVPN3_DIR", openvpn3_source)
        .define("OPENVPN_CONNECT_ASIO_INCLUDE", &dependencies.asio_include)
        .define("OPENVPN_CONNECT_LZ4_INCLUDE", &dependencies.lz4_include)
        .define(
            "OPENVPN_CONNECT_OPENSSL_INCLUDE",
            &dependencies.openssl_include,
        )
        .define("OPENVPN_CONNECT_FORCE_NULL_TUN", "OFF")
        .define(
            "OPENVPN_CONNECT_ENABLE_DCO",
            if features.dco { "ON" } else { "OFF" },
        )
        .define(
            "OPENVPN_CONNECT_EXTERNAL_TRANSPORT",
            if features.external_transport {
                "ON"
            } else {
                "OFF"
            },
        )
        .define(
            "OPENVPN_CONNECT_EXTERNAL_TUN",
            if features.external_tun { "ON" } else { "OFF" },
        )
        .define(
            "OPENVPN_CONNECT_USE_TUN_BUILDER",
            if matches!(target.os, "android" | "ios") || target.env == "ohos" {
                "ON"
            } else {
                "OFF"
            },
        );

    if let Some(path) = &dependencies.lz4_lib {
        config.define("OPENVPN_CONNECT_LZ4_LIBRARY_DIR", path);
    }
    if let Some(path) = &dependencies.openssl_lib {
        config.define("OPENVPN_CONNECT_OPENSSL_LIBRARY_DIR", path);
    }
    configure_cross_toolchain(&mut config, target, mode);

    let destination = config.build();
    let lib_dir = destination.join("lib");
    if target.env == "ohos" && target.arch == "arm" {
        install_ohos_atomic_compatibility_archive(&lib_dir, target);
    }
    let runtime = destination.join("bin");
    let library_file = lib_dir.join(library_filename(target.os, target.env, mode));
    assert!(
        library_file.is_file(),
        "CMake completed but did not produce {}",
        library_file.display()
    );
    NativeLibrary {
        lib_dir,
        runtime_dir: runtime.is_dir().then_some(runtime),
        _library_file: library_file,
    }
}

fn install_ohos_atomic_compatibility_archive(lib_dir: &Path, target: BuildTarget<'_>) {
    // Rust's tier-2 ARMv7 OHOS target requests `-latomic`, while the official
    // SDK exposes those exact __atomic_* implementations only through its
    // compiler-rt builtins archive.  Give the SDK archive the conventional
    // linker name in this build output; no prebuilt library enters the crate.
    let sdk = ohos_sdk_native();
    let compiler = target_c_compiler(target, &sdk);
    let output = Command::new(&compiler)
        .arg("-print-libgcc-file-name")
        .output()
        .unwrap_or_else(|error| panic!("failed to query {}: {error}", compiler.display()));
    assert!(
        output.status.success(),
        "{} could not locate its compiler runtime",
        compiler.display()
    );
    let builtins = PathBuf::from(
        String::from_utf8(output.stdout)
            .expect("target compiler returned a non-UTF-8 runtime path")
            .trim(),
    );
    assert!(
        builtins.is_file(),
        "target compiler runtime does not exist: {}",
        builtins.display()
    );
    let atomic = lib_dir.join("libatomic.a");
    fs::copy(&builtins, &atomic).unwrap_or_else(|error| {
        panic!(
            "failed to expose {} as {}: {error}",
            builtins.display(),
            atomic.display()
        )
    });
}

fn target_c_compiler(target: BuildTarget<'_>, sdk: &Path) -> PathBuf {
    let prefix = match target.arch {
        "aarch64" => "aarch64",
        "arm" => "armv7",
        "x86_64" => "x86_64",
        arch => panic!("unsupported OpenHarmony compiler architecture: {arch}"),
    };
    sdk.join(format!("llvm/bin/{prefix}-unknown-linux-ohos-clang"))
}

fn configure_cross_toolchain(config: &mut cmake::Config, target: BuildTarget<'_>, mode: LinkMode) {
    // Rust models OpenHarmony as a Linux OS with the dedicated `ohos`
    // environment (for example `aarch64-unknown-linux-ohos`).  Checking only
    // `target_os` silently selected the host/default CMake compiler.
    if target.env == "ohos" {
        let sdk = ohos_sdk_native();
        config
            .define(
                "CMAKE_TOOLCHAIN_FILE",
                sdk.join("build/cmake/ohos.toolchain.cmake"),
            )
            .define("OHOS_ARCH", ohos_arch(target.arch))
            .define(
                "OHOS_STL",
                if mode == LinkMode::Static {
                    "c++_static"
                } else {
                    "c++_shared"
                },
            );
    } else if target.os == "android" {
        let ndk = android_ndk();
        config
            .define(
                "CMAKE_TOOLCHAIN_FILE",
                ndk.join("build/cmake/android.toolchain.cmake"),
            )
            .define("ANDROID_ABI", android_abi(target.arch))
            .define("ANDROID_PLATFORM", "android-24");
    } else if target.os == "ios" {
        config
            .define("CMAKE_SYSTEM_NAME", "iOS")
            .define("CMAKE_OSX_ARCHITECTURES", apple_arch(target.arch))
            .define(
                "CMAKE_OSX_SYSROOT",
                if target.triple.ends_with("-ios-sim") || target.arch == "x86_64" {
                    "iphonesimulator"
                } else {
                    "iphoneos"
                },
            );
    } else if target.triple != env::var("HOST").unwrap_or_default() {
        println!(
            "cargo:warning=building {} requires a working Cargo/CMake cross compiler and target dependencies",
            target.triple
        );
    }
}

fn android_ndk() -> PathBuf {
    for variable in ["ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME"] {
        if let Some(path) = env::var_os(variable) {
            return PathBuf::from(path);
        }
    }
    panic!("Android NDK is not configured; set ANDROID_NDK_HOME, ANDROID_NDK_ROOT, or NDK_HOME");
}

fn ohos_sdk_native() -> PathBuf {
    let (candidate, source) = if let Some(path) = env::var_os(OHOS_SDK_NATIVE_ENV) {
        (PathBuf::from(path), OHOS_SDK_NATIVE_ENV)
    } else if let Some(path) = env::var_os("OHOS_NDK_HOME") {
        let root = PathBuf::from(path);
        let native = root.join("native");
        (
            if native.join("sysroot").is_dir() {
                native
            } else {
                root
            },
            "OHOS_NDK_HOME",
        )
    } else {
        panic!(
            "OpenHarmony Native SDK is not configured; set {OHOS_SDK_NATIVE_ENV} or OHOS_NDK_HOME"
        );
    };
    assert!(
        candidate.join("sysroot").is_dir()
            && candidate.join("build/cmake/ohos.toolchain.cmake").is_file(),
        "{source}={} is not a complete OpenHarmony Native SDK root",
        candidate.display()
    );
    candidate
}

fn ohos_arch(arch: &str) -> &'static str {
    match arch {
        "aarch64" => "arm64-v8a",
        "arm" => "armeabi-v7a",
        "x86_64" => "x86_64",
        _ => panic!("unsupported OpenHarmony architecture: {arch}"),
    }
}

fn android_abi(arch: &str) -> &'static str {
    match arch {
        "aarch64" => "arm64-v8a",
        "arm" => "armeabi-v7a",
        "x86_64" => "x86_64",
        "x86" => "x86",
        _ => panic!("unsupported Android architecture: {arch}"),
    }
}

fn apple_arch(arch: &str) -> &'static str {
    match arch {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        _ => panic!("unsupported Apple architecture: {arch}"),
    }
}

fn emit_native_link(native: &NativeLibrary, target_os: &str, target_env: &str, mode: LinkMode) {
    println!(
        "cargo:rustc-link-search=native={}",
        native.lib_dir.display()
    );
    println!("cargo:rustc-link-lib={}=openvpn3_core", mode.cargo_kind());

    if mode == LinkMode::Dynamic {
        emit_rpath(&native.lib_dir, target_os);
        if let Some(runtime) = &native.runtime_dir {
            emit_rpath(runtime, target_os);
        }
        return;
    }

    match target_os {
        "macos" | "ios" => {
            println!("cargo:rustc-link-lib=c++");
            for framework in [
                "CoreFoundation",
                "IOKit",
                "CoreServices",
                "SystemConfiguration",
            ] {
                println!("cargo:rustc-link-lib=framework={framework}");
            }
        }
        "windows" => {
            for library in [
                "fwpuclnt", "iphlpapi", "wininet", "setupapi", "rpcrt4", "wtsapi32", "ws2_32",
                "wsock32",
            ] {
                println!("cargo:rustc-link-lib={library}");
            }
            if target_env != "msvc" {
                println!("cargo:rustc-link-lib=stdc++");
                println!("cargo:rustc-link-lib=winpthread");
            }
        }
        _ if target_env == "ohos" => {
            println!("cargo:rustc-link-lib=c++_static");
            println!("cargo:rustc-link-lib=c++abi");
            println!("cargo:rustc-link-lib=unwind");
            println!("cargo:rustc-link-lib=pthread");
        }
        _ => {
            println!("cargo:rustc-link-lib=stdc++");
            println!("cargo:rustc-link-lib=pthread");
        }
    }
}

fn emit_discovered_dependency_paths(dependencies: &DependencyPaths) {
    for path in [&dependencies.openssl_lib, &dependencies.lz4_lib]
        .into_iter()
        .flatten()
    {
        println!("cargo:rustc-link-search=native={}", path.display());
    }
}

fn is_host_build() -> bool {
    env::var("TARGET").ok() == env::var("HOST").ok()
}

fn emit_rpath(path: &Path, target_os: &str) {
    if matches!(target_os, "macos" | "linux") {
        println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path.display());
    }
}
