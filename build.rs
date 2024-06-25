use std::process::Command;

fn main() {
    // Create the output directory if it does not exist
    std::fs::create_dir_all("target/bpfel-unknown-none/debug").unwrap();

    // Compile the eBPF program
    let status = Command::new("clang")
        .args(&[
            "-O2",
            "-target",
            "bpf",
            "-c",
            "src/bpf/block_http_requests.c",
            "-o",
            "target/bpfel-unknown-none/debug/block_http_requests.o",
        ])
        .status()
        .expect("Failed to execute clang");

    if !status.success() {
        panic!("Failed to compile eBPF program");
    }
}
