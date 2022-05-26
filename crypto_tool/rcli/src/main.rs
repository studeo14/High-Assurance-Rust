/// Encryption CLI
/// Author: Steven Frederiksen
/// Derived From: https://highassurance.rs/chp2/cli.html
use chacha20poly1305::aead::{NewAead, stream};
use chacha20poly1305::{ChaCha20Poly1305};
use clap::Parser;
use colored::Colorize;
use std::fs::File;
use std::io::prelude::{Write, Read, Seek};
use anyhow::{anyhow, Result};

/// File en/decryption
#[derive(Parser, Debug)]
struct Args {
    /// Tell the tool to only predict if the given file is encrypted
    #[clap(short, long)]
    predict_only: bool,

    /// Overwrite file with en/decryption result
    #[clap(short, long)]
    overwrite: bool,

    /// Name of file
    #[clap(short, long, value_name = "FILE_NAME", required = true)]
    file: String,

    /// En/Decryption key
    #[clap(short, long, required = true, value_name = "KEY")]
    key: String,

    /// Nonce
    #[clap(short, long, required = true, value_name = "NONCE")]
    nonce: String,

    /// Force Encryption
    #[clap(long, conflicts_with = "decrypt")]
    encrypt: bool,

    /// Force Decryption
    #[clap(long, conflicts_with = "encrypt")]
    decrypt: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Open the file for read/write
    let mut buffer = [0u8; 500];
    let mut file = File::options().read(true).open(&args.file)?;

    // Read the first chunk of the file
    let read_count = file.read(&mut buffer)?;
    let total_bits = read_count * 8;
    let mut total_ones = 0;
    let mut total_below_128 = 0;
    for &byte in &buffer[..read_count] {
        total_ones += byte.count_ones();
        if byte < 128 {
            total_below_128 += 1;
        }
    }
    let ones_ratio = total_ones as f32 / total_bits as f32;
    let ascii_ratio = total_below_128 as f32 / read_count as f32;

    let encrypt = match (args.encrypt, args.decrypt) {
        (true, false) => true,
        (false, true) => false,
        _ => ascii_ratio >= 0.990,
    };

    if !args.predict_only {
        // read in user arguments
        // Note:
        // Enfore length here
        if args.key.len() != 32 {
            return Err(anyhow!(
                "Key must be 32 characters long",
            ));
        }
        let key = args.key.as_bytes();
        let nonce = args.nonce.as_bytes();

        // create the cipher instance
        let cipher = ChaCha20Poly1305::new(key.as_ref().into());

        // Overwrite the existing file check
        let filename = if args.overwrite {
            println!("{}; You are overwriting {}", "WARNING".yellow(), args.file.red());
            args.file.clone()
        } else {
            if encrypt {
                format!("{}.enc", args.file)
            } else {
                format!("{}.denc", args.file)
            }
        };
        println!("Writing result to {}", filename.green());

        let mut output_file = File::options()
            .create(true)
            .truncate(true)
            .write(true)
            .open(filename)?;

        // En/Decrypt the file
        if encrypt {
            let mut stream_encryptor = stream::EncryptorBE32::from_aead(cipher, nonce.as_ref().into());
            // reset file location
            file.rewind()?;
            let mut buffer = [0u8; 500];
            loop {
                let read_count = file.read(&mut buffer)?;
                if read_count == 500 {
                    let ciphertext = stream_encryptor
                        .encrypt_next(buffer.as_slice())
                        .map_err(|err| anyhow!("Encrypting {}",  err))?;
                    output_file.write(&ciphertext)?;
                } else {
                    let ciphertext = stream_encryptor
                        .encrypt_last(&buffer[..read_count])
                        .map_err(|err| anyhow!("Encrypting {}",  err))?;
                    output_file.write(&ciphertext)?;
                    break;
                }
            }
            println!("Encrypted {}", args.file.green());
        } else {
            let mut stream_decryptor = stream::DecryptorBE32::from_aead(cipher, nonce.as_ref().into());
            // reset file location
            file.rewind()?;
            let mut buffer = [0u8; 516];
            loop {
                let read_count = file.read(&mut buffer)?;
                if read_count == 516 {
                    let plaintext = stream_decryptor
                        .decrypt_next(buffer.as_slice())
                        .map_err(|err| anyhow!("Decrypting {}", err))?;
                    output_file.write(&plaintext)?;
                } else if read_count == 0 {
                    break;
                } else {
                    let plaintext = stream_decryptor
                        .decrypt_last(&buffer[..read_count])
                        .map_err(|err| anyhow!("Decrypting {}", err))?;
                    output_file.write(&plaintext)?;
                    break;
                }
            }
            println!("Decrypted {}", args.file.green());
        }

    } else {
        println!(
            "Distribution of ones: {}/{} ({}%)",
            total_ones,
            total_bits,
            ones_ratio * 100.0
        );
        println!(
            "Distribution of < 128: {}/{} ({}%)",
            total_below_128,
            read_count,
            ascii_ratio * 100.0
        );
    }

    Ok(())
}
