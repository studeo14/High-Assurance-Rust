/// Encryption CLI
/// Author: Steven Frederiksen
/// Derived From: https://highassurance.rs/chp2/cli.html
use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clap::Parser;
use colored::Colorize;
use std::fs::File;
use std::io;
use std::io::prelude::{Read, Write};

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
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    // Open the file for read/write
    let mut contents = Vec::new();
    let mut file = File::options().read(true).open(&args.file)?;

    // Read the file
    file.read_to_end(&mut contents)?;
    let total_bits = contents.len() * 8;
    let mut total_ones = 0;
    let mut total_below_128 = 0;
    for byte in &contents {
        total_ones += byte.count_ones();
        if byte < &128 {
            total_below_128 += 1;
        }
    }
    let ones_ratio = total_ones as f32 / total_bits as f32;
    let ascii_ratio = total_below_128 as f32 / contents.len() as f32;

    let encrypt = ascii_ratio >= 0.990;

    if !args.predict_only {
        // read in user arguments
        // Note:
        // Enfore length here
        if args.key.len() != 32 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Key must be 32 characters long",
            ));
        }
        let key = Key::from_slice(args.key.as_bytes());
        let nonce = Nonce::from_slice(args.nonce.as_bytes());

        // create the cipher instance
        let cipher = ChaCha20Poly1305::new(key);

        // En/Decrypt the file
        let new_contents = if encrypt {
            let ciphertext = cipher.encrypt(nonce, contents.as_slice());
            println!("Encrypted {}", args.file);
            ciphertext
        } else {
            let plaintext = cipher.decrypt(nonce, contents.as_slice());
            println!("Decrypted {}", args.file);
            plaintext
        };

        if let Err(e) = new_contents {
            println!("Failure to process file {}", e);
        } else {
            // Overwrite the existing file check TODO
            let filename = if args.overwrite {
                println!("{}; You are overwriting {}", "WARNING".yellow(), args.file.red());
                args.file
            } else {
                if encrypt {
                    format!("{}.enc", args.file)
                } else {
                    format!("{}.denc", args.file)
                }
            };
            println!("Writing result to {}", filename.green());
            let mut file = File::options()
                .create(true)
                .truncate(true)
                .write(true)
                .open(filename)?;
            file.write_all(&new_contents.unwrap())?;
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
            contents.len(),
            ascii_ratio * 100.0
        );
    }

    Ok(())
}
