use aya::programs::{tc, TcAttachType};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpf = Bpf::load_file("target/bpfel-unknown-none/debug/block_http_requests.o")?;
    BpfLogger::init(&mut bpf)?;

    let program: &mut tc::Tc = bpf.program_mut("block_http_requests").unwrap().try_into()?;
    program.load()?;

    let ifindex = get_ifindex("eth0")?; // Change "eth0" to your network interface
    program.attach(ifindex, TcAttachType::Ingress)?;

    println!("Blocking HTTP requests. Press Ctrl+C to exit.");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}

fn get_ifindex(iface_name: &str) -> Result<i32, Box<dyn std::error::Error>> {
    use std::fs::File;
    use std::io::{self, Read};

    let mut file = File::open(format!("/sys/class/net/{}/ifindex", iface_name))?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let ifindex: i32 = contents.trim().parse()?;
    Ok(ifindex)
}
