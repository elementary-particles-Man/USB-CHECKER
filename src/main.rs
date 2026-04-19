use anyhow::{anyhow, Result};
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "usb-checker")]
#[command(about = "Surgical USB Integrity Checker (Flash Fraud Detection)", long_about = None)]
struct Cli {
    /// Target device (e.g., /dev/sdX)
    device: PathBuf,

    /// Write mode (DESTRUCTIVE: overwrites data with unique patterns)
    #[arg(short, long)]
    write: bool,

    /// Block size in bytes (default: 1MiB)
    #[arg(short, long, default_value = "1048576")]
    block_size: usize,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.write {
        run_write_phase(&cli.device, cli.block_size)?;
    }
    
    run_verify_phase(&cli.device, cli.block_size)?;

    Ok(())
}

fn run_write_phase(device_path: &PathBuf, block_size: usize) -> Result<()> {
    println!("--- [PHASE 1/2] Destructive Write (Pattern Injection) ---");
    let mut file = OpenOptions::new()
        .write(true)
        .open(device_path)
        .map_err(|e| anyhow!("Failed to open device for writing: {}", e))?;

    let device_size = file.metadata()?.len();
    let num_blocks = device_size / block_size as u64;

    let pb = ProgressBar::new(num_blocks);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} blocks ({eta})")?
        .progress_chars("#>-"));

    for i in 0..num_blocks {
        let pattern = generate_pattern(i, block_size);
        file.write_all(&pattern)?;
        pb.inc(1);
    }
    
    pb.finish_with_message("Write complete.");
    println!("--- Flushing hardware buffers... ---");
    file.sync_all()?;
    Ok(())
}

fn run_verify_phase(device_path: &PathBuf, block_size: usize) -> Result<()> {
    println!("--- [PHASE 2/2] Integrity Verification (Pattern Audit) ---");
    let mut file = File::open(device_path)?;
    let device_size = file.metadata()?.len();
    let num_blocks = device_size / block_size as u64;

    let pb = ProgressBar::new(num_blocks);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.yellow/red}] {pos}/{len} blocks ({eta})")?
        .progress_chars("#>-"));

    let mut buffer = vec![0u8; block_size];
    let mut errors = 0;

    for i in 0..num_blocks {
        file.seek(SeekFrom::Start(i * block_size as u64))?;
        file.read_exact(&mut buffer)?;
        
        let expected = generate_pattern(i, block_size);
        if buffer != expected {
            pb.println(format!("[ERROR] Data corruption detected at block {} (offset 0x{:x})", i, i * block_size as u64));
            errors += 1;
        }
        pb.inc(1);
    }

    pb.finish_with_message("Verification complete.");
    
    if errors == 0 {
        println!("--- [RESULT] USB Integrity VERIFIED. No fraud detected. ---");
    } else {
        println!("--- [RESULT] FATAL: {} corrupted blocks detected. This device is UNSAFE. ---", errors);
    }

    Ok(())
}

fn generate_pattern(block_index: u64, size: usize) -> Vec<u8> {
    // Generate a unique, non-compressible pattern for each block based on its index
    let mut hasher = Sha256::new();
    hasher.update(b"TUFF-WARDEN-V1");
    hasher.update(block_index.to_le_bytes());
    let hash = hasher.finalize();

    let mut pattern = Vec::with_capacity(size);
    while pattern.len() < size {
        let remaining = size - pattern.len();
        let to_add = std::cmp::min(remaining, hash.len());
        pattern.extend_from_slice(&hash[..to_add]);
    }
    pattern
}
