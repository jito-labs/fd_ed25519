use std::{env, path::PathBuf};

fn main() {
    if env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default() == "x86_64"
        && std::is_x86_feature_detected!("avx512f")
    {
        println!("cargo:rustc-cfg=fd_has_avx512");
        println!("cargo:warning=Build: Detected AVX512F support on x86_64. Enabling AVX512 features for C compilation and bindings.");
    };

    let vendor_dir = PathBuf::from("vendor");

    // 2. List all header files, these paths are relative to the project root.
    let header_files = [
        "ballet/fd_ballet_base.h",
        "ballet/sha512/fd_sha512.h",
        "ballet/ed25519/fd_ed25519.h",
        "ballet/ed25519/fd_curve25519.h",
        "ballet/ed25519/avx512/fd_r43x6_ge.h",
        "ballet/ed25519/avx512/fd_r43x6.h",
        "util/fd_util.h",
    ];

    // Base C and Assembly source files to be compiled
    let base_source_files = vec![
        "ballet/ed25519/fd_ed25519_user.c",
        "ballet/ed25519/fd_curve25519.c",
        "ballet/ed25519/fd_curve25519_scalar.c",
        "ballet/ed25519/fd_f25519.c",
        "ballet/sha512/fd_sha512.c",
        "util/fd_util.c",
        "ballet/sha512/fd_sha512_core_avx2.S",
        "ballet/ed25519/avx512/fd_r43x6_ge.c",
        "ballet/ed25519/avx512/fd_r43x6.c",
    ];

    let source_files_to_compile = base_source_files.clone();

    // 3. Compile the C code into a static library.
    let mut cc_build = cc::Build::new();
    cc_build
        .files(
            source_files_to_compile
                .iter()
                .map(|path_str| vendor_dir.join(path_str)),
        )
        .include(&vendor_dir) // Allows #include "ballet/..." and #include "util/..."
        .flag("-DFD_HAS_BACKTRACE=0")
        .flag("-DFD_USING_CLANG=1")
        .flag("-march=znver4")
        .flag("-mtune=znver4")
        .flag("-Werror")
        .flag("-Wall")
        .flag("-Wextra")
        .flag("-Wpedantic")
        .flag("-Wstrict-aliasing=2")
        .flag("-Wconversion")
        .flag("-Wdouble-promotion")
        .flag("-Wformat-security")
        .flag("-Wimplicit-fallthrough")
        .flag("-Wno-address-of-packed-member")
        .flag("-Wno-unused-command-line-argument")
        .flag("-Wno-bitwise-instead-of-logical")
        .flag("-Wno-gnu-zero-variadic-macro-arguments")
        .flag("-O3")
        .flag("-ffast-math")
        .flag("-fno-associative-math")
        .flag("-fno-reciprocal-math")
        .flag("-DFD_HAS_OPTIMIZATION=1")
        .flag("-g")
        .flag("-fno-omit-frame-pointer")
        .flag("-fPIC")
        .flag("-Wl,-z,relro,-z,now")
        .flag("-fstack-protector-strong")
        .flag("-D_FORTIFY_SOURCE=2")
        .flag("-DFD_HAS_SHANI=1")
        .flag("-DFD_HAS_INT128=1")
        .flag("-DFD_HAS_DOUBLE=1")
        .flag("-DFD_HAS_ALLOCA=1")
        .flag("-DFD_HAS_OPENSSL=1")
        .flag("-DFD_HAS_X86=1")
        .flag("-DFD_HAS_SSE=1")
        .flag("-DFD_HAS_AVX=1")
        .flag("-DFD_HAS_GFNI=1")
        .flag("-DFD_IS_X86_64=1")
        .flag("-DFD_HAS_AESNI=1")
        .flag("-DFD_HAS_AVX512=1")
        .flag("-D_XOPEN_SOURCE=700")
        .flag("-DFD_HAS_HOSTED=1")
        .flag("-pthread")
        .flag("-DFD_HAS_THREADS=1") // Ensure these thread flags are correct for your use case
        .flag("-DFD_HAS_ATOMIC=1")
        .flag("-mfpmath=sse")
        .flag("-falign-functions=32")
        // .flag("-Xclang -target-feature -Xclang +fast-vector-fsqrt") // Clang specific, ensure it's intended
        .flag("-DFD_HAS_UCONTEXT=1")
        .flag("-DFD_BUILD_INFO=\"build/native/clang/info\"")
        .flag("-std=c17")
        .flag("-fwrapv");

    cc_build.compile("libballet_ed25519.a");

    // Tell cargo to link the compiled static library.
    println!("cargo:rustc-link-lib=static=ballet_ed25519");

    // Tell cargo to invalidate the built crate whenever the wrapper header or C sources change.
    println!("cargo:rerun-if-changed=wrapper.h");
    // Everything below lives inside vendor_dir. List each path **relative** to vendor_dir once:
    for rel in header_files.iter() {
        println!("cargo:rerun-if-changed={}", vendor_dir.join(rel).display());
    }

    // Rerun if any of the *potentially* compiled C/S files change.
    let all_possible_source_files_for_rerun = base_source_files.clone();
    for rel_path_str in all_possible_source_files_for_rerun.iter() {
        println!(
            "cargo:rerun-if-changed={}",
            vendor_dir.join(rel_path_str).display()
        );
    }

    // 4. Generate the bindings.
    let mut bindgen_builder = bindgen::Builder::default();
    bindgen_builder = bindgen_builder
        .header("wrapper.h")
        // Tell bindgen where to find included C headers (paths passed to clang)
        .clang_arg(format!(
            "-I{}",
            vendor_dir
                .canonicalize()
                .expect("Cannot canonicalize vendor dir")
                .display()
        ))
        // Add clang args for bindgen based on the provided flags
        .clang_arg("-DFD_HAS_BACKTRACE=0")
        .clang_arg("-DFD_USING_CLANG=1")
        .clang_arg("-march=znver4") // Bindgen also needs to know target architecture for correct parsing
        .clang_arg("-DFD_HAS_OPTIMIZATION=1")
        .clang_arg("-DFD_HAS_SHANI=1")
        .clang_arg("-DFD_HAS_INT128=1")
        .clang_arg("-DFD_HAS_DOUBLE=1")
        .clang_arg("-DFD_HAS_ALLOCA=1")
        .clang_arg("-DFD_HAS_THREADS=1")
        .clang_arg("-DFD_HAS_OPENSSL=1")
        .clang_arg("-DFD_HAS_X86=1")
        .clang_arg("-DFD_HAS_SSE=1")
        .clang_arg("-DFD_HAS_AVX=1")
        .clang_arg("-DFD_HAS_GFNI=1")
        .clang_arg("-DFD_IS_X86_64=1")
        .clang_arg("-DFD_HAS_AESNI=1")
        .clang_arg("-DFD_HAS_AVX512=1")
        .clang_arg("-D_XOPEN_SOURCE=700")
        .clang_arg("-DFD_HAS_HOSTED=1")
        .clang_arg("-DFD_HAS_ATOMIC=1")
        .clang_arg("-DFD_HAS_UCONTEXT=1")
        .clang_arg("-DFD_BUILD_INFO=\"build/native/clang/info\"")
        .clang_arg("-std=c17");

    let bindings = bindgen_builder
        .allowlist_function("fd_ed25519_public_from_private")
        .allowlist_function("fd_ed25519_sign")
        .allowlist_function("fd_ed25519_verify")
        .allowlist_function("fd_ed25519_verify_batch_single_msg")
        .allowlist_function("fd_ed25519_point_frombytes")
        .allowlist_function("fd_ed25519_strerror")
        .allowlist_function("fd_sha512_init")
        .allowlist_type("fd_sha512_t") // Ensure opaque types are known
        .allowlist_type("fd_ed25519_point_t")
        .allowlist_var("FD_ED25519_SUCCESS")
        .allowlist_var("FD_ED25519_ERR_SIG")
        .allowlist_var("FD_ED25519_ERR_PUBKEY")
        .allowlist_var("FD_ED25519_ERR_MSG")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bindings_file_path = out_path.join("bindings.rs");
    bindings
        .write_to_file(&bindings_file_path)
        .expect("Couldn't write bindings!");
}
