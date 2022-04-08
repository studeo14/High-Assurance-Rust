/// Encryption CLI
/// Author: Steven Frederiksen
/// Derived From: https://highassurance.rs/chp2/cli.html
use chacha20poly1305::aead::{AeadInPlace, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::Parser;
use std::fs::File;
use std::io;
use std::io::prelude::{Read, Seek, Write};

/// RC4 file en/decryption
#[derive(Parser, Debug)]
struct Args {
    /// Name of file
    #[clap(short, long, required = true, value_name = "FILE_NAME")]
    file: String,

    /// En/Decryption key
    #[clap(
        short,
        long,
        required = true,
        value_name = "KEY",
    )]
    key: String,

    /// Nonce
    #[clap(
        short,
        long,
        required = true,
        value_name = "NONCE",
    )]
    nonce: String,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();
    let mut contents = Vec::new();

    // read in user arguments
    // Note:
    // Enfore length here
    if args.key.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::Other, "Key must be 32 characters long"));
    }
    let key = Key::from_slice(args.key.as_bytes());
    let nonce = Nonce::from_slice(args.nonce.as_bytes());

    // create the cipher instance
    let cipher = ChaCha20Poly1305::new(key);

    // Open the file for read/write
    let mut file = File::options().read(true).write(true).open(&args.file)?;

    // Read the file
    file.read_to_end(&mut contents)?;
    let total_bits = contents.len() * 8;
    let mut total_ones = 0;
    for byte in &contents {
        total_ones += byte.count_ones();
    }

    println!("Distribution of ones: {}/{} ({}%)", total_ones, total_bits, (total_ones as f32 / total_bits as f32) * 100.0);

    // En/Decrypt the file
    cipher
        .encrypt_in_place(nonce, b"", &mut contents)
        .expect("encryption failure");

    // Overwrite the existing file
    file.rewind()?; // Start at the beginning
    file.write_all(&contents)?;

    // Success
    println!("Processed {}", args.file);

    Ok(())
}
