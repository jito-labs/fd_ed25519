use std::{env, path::PathBuf};

fn main() {
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let is_x86_64 = target_arch == "x86_64";

    let use_avx512 = if is_x86_64 {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        let has_avx512 = std::is_x86_feature_detected!("avx512f");

        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        let has_avx512 = false;

        if has_avx512 {
            println!("cargo:rustc-cfg=fd_has_avx512");
            println!("cargo:warning=Build: Detected AVX512F support on x86_64, Enabling AVX512 features for C compilation and bindings.");
            true
        } else {
            println!("cargo:warning=Build: AVX512F support not detected, AVX512 C features and defines will be disabled.");
            false
        }
    } else {
        println!("cargo:warning=Build: Not on x86_64, AVX512 C features and defines will be disabled.");
        false
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
        "util/log/fd_log.h",
    ];

    // Base C and Assembly source files to be compiled
    let base_source_files = vec![
        "ballet/ed25519/fd_ed25519_user.c",
        "ballet/ed25519/fd_curve25519.c",
        "ballet/ed25519/fd_curve25519_scalar.c",
        "ballet/ed25519/fd_f25519.c",
        "ballet/sha512/fd_sha512.c",
        "util/fd_util.c",
        "util/log/fd_log.c",
    ];

    let avx512_source_files = vec![
        "ballet/sha512/fd_sha512_core_avx2.S",
        "ballet/ed25519/avx512/fd_r43x6_ge.c",
        "ballet/ed25519/avx512/fd_r43x6.c",
    ];

    let mut source_files_to_compile = base_source_files.clone();
    if use_avx512 {
        source_files_to_compile.extend(avx512_source_files.clone());
    }

    // 3. Compile the C code into a static library.
    // flags taken from command:
    // clang -isystem ./opt/include -DFD_HAS_BACKTRACE=0 -DFD_USING_CLANG=1 -march=native -mtune=native -Werror -Wall -Wextra -Wpedantic -Wstrict-aliasing=2 -Wconversion -Wdouble-promotion -Wformat-security -Wimplicit-fallthrough -Wno-address-of-packed-member -Wno-unused-command-line-argument -Wno-bitwise-instead-of-logical -Wno-gnu-zero-variadic-macro-arguments -O3 -ffast-math -fno-associative-math -fno-reciprocal-math -DFD_HAS_OPTIMIZATION=1 -g -fno-omit-frame-pointer -fPIC -Wl,-z,relro,-z,now -fstack-protector-strong -D_FORTIFY_SOURCE=2 -DFD_HAS_SHANI=1 -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_THREADS=1 -DFD_HAS_OPENSSL=1 -DFD_HAS_X86=1 -DFD_HAS_SSE=1 -DFD_HAS_AVX=1 -DFD_HAS_GFNI=1 -DFD_IS_X86_64=1 -DFD_HAS_AESNI=1 -DFD_HAS_AVX512=1 -D_XOPEN_SOURCE=700 -DFD_HAS_HOSTED=1 -pthread -DFD_HAS_THREADS=1 -DFD_HAS_ATOMIC=1 -mfpmath=sse -falign-functions=32 -Xclang -target-feature -Xclang +fast-vector-fsqrt -DFD_HAS_UCONTEXT=1 -DFD_BUILD_INFO=\"build/native/clang/info\" -std=c17 -fwrapv -M -MP src/ballet/ed25519/fd_ed25519_user.c -o build/native/clang/obj/ballet/ed25519/fd_ed25519_user.d.tmp
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
        .flag("-march=native")
        .flag("-mtune=native")
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
        .flag("-fstack-protector-strong")
        .flag("-D_FORTIFY_SOURCE=2")
        .flag("-DFD_HAS_INT128=1")
        .flag("-DFD_HAS_DOUBLE=1")
        .flag("-DFD_HAS_ALLOCA=1")
        .flag("-DFD_HAS_OPENSSL=1")
        .flag("-D_XOPEN_SOURCE=700")
        .flag("-DFD_HAS_HOSTED=1")
        .flag("-pthread")
        .flag("-DFD_HAS_THREADS=1")
        .flag("-DFD_HAS_ATOMIC=1")
        .flag("-falign-functions=32")
        .flag("-DFD_HAS_UCONTEXT=1")
        .flag("-DFD_BUILD_INFO=\"build/native/clang/info\"")
        .flag("-std=c17")
        .flag("-fwrapv");

    if is_x86_64 {
        cc_build
            .flag("-Werror") // fails on macos
            .flag("-DFD_HAS_X86=1")
            .flag("-DFD_IS_X86_64=1")
            .flag("-DFD_HAS_SSE=1")
            .flag("-DFD_HAS_AESNI=1")
            .flag("-DFD_HAS_SHANI=1")
            .flag("-mfpmath=sse")
            .flag("-Wl,-z,relro,-z,now");
        if use_avx512 {
            cc_build
                .flag("-DFD_HAS_AVX=1")
                .flag("-DFD_HAS_AVX512=1")
                .flag("-DFD_HAS_GFNI=1");
        }
    }

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
    let all_possible_source_files_for_rerun = {
        let mut temp = base_source_files.clone();
        temp.extend(avx512_source_files.clone());
        temp
    };
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
        .clang_arg("-march=native") // Bindgen also needs to know target architecture for correct parsing
        .clang_arg("-DFD_HAS_OPTIMIZATION=1")
        .clang_arg("-DFD_HAS_INT128=1")
        .clang_arg("-DFD_HAS_DOUBLE=1")
        .clang_arg("-DFD_HAS_ALLOCA=1")
        .clang_arg("-DFD_HAS_THREADS=1")
        .clang_arg("-DFD_HAS_OPENSSL=1")
        .clang_arg("-D_XOPEN_SOURCE=700")
        .clang_arg("-DFD_HAS_HOSTED=1")
        .clang_arg("-DFD_HAS_ATOMIC=1")
        .clang_arg("-DFD_HAS_UCONTEXT=1")
        .clang_arg("-DFD_BUILD_INFO=\"build/native/clang/info\"")
        .clang_arg("-std=c17");

    if is_x86_64 {
        bindgen_builder = bindgen_builder
            .clang_arg("-DFD_HAS_X86=1")
            .clang_arg("-DFD_IS_X86_64=1")
            .clang_arg("-DFD_HAS_SSE=1")
            .clang_arg("-DFD_HAS_AESNI=1")
            .clang_arg("-DFD_HAS_SHANI=1");
        if use_avx512 {
            bindgen_builder = bindgen_builder
                .clang_arg("-DFD_HAS_AVX=1")
                .clang_arg("-DFD_HAS_AVX512=1")
                .clang_arg("-DFD_HAS_GFNI=1");
        }
    }

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
