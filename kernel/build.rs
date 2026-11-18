fn main() {
    let dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    println!("cargo:rustc-link-arg-bins=-T{dir}/linker.ld");
    // Keep the image small and the layout predictable.
    println!("cargo:rustc-link-arg-bins=-zmax-page-size=0x1000");
    println!("cargo:rustc-link-arg-bins=--no-undefined");
    println!("cargo:rerun-if-changed=linker.ld");
    println!("cargo:rerun-if-env-changed=KALKAN_INIT_BLAKE2B");
    println!("cargo:rerun-if-env-changed=KALKAN_SANDBOX_BLAKE2B");
}
