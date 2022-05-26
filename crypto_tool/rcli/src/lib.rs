//! Encryption CLI Lib
//! Author: Steven Frederiksen
use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{stream, NewAead},
    ChaCha20Poly1305,
};
use clap::Parser;
use colored::Colorize;
use std::{
    fs::File,
    io::{Read, Seek, Write},
};
/// File en/decryption
#[derive(Parser, Debug)]
pub struct Args {
    /// Tell the tool to only predict if the given file is encrypted
    #[clap(short, long)]
    pub predict_only: bool,

    /// Overwrite file with en/decryption result
    #[clap(short, long)]
    pub overwrite: bool,

    /// Name of file
    #[clap(short, long, value_name = "FILE_NAME", required = true)]
    pub file: String,

    /// En/Decryption key
    #[clap(short, long, required = true, value_name = "KEY")]
    pub key: String,

    /// Nonce
    #[clap(short, long, required = true, value_name = "NONCE")]
    pub nonce: String,

    /// Force Encryption
    #[clap(long, conflicts_with = "decrypt")]
    pub encrypt: bool,

    /// Force Decryption
    #[clap(long, conflicts_with = "encrypt")]
    pub decrypt: bool,
}

pub fn encrypt_or_decrypt(args: &Args, file: &mut File) -> Result<bool> {
    let mut buffer = [0u8; 500];
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

    if args.predict_only {
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

    Ok(encrypt)
}

pub fn stream_encrypt(
    args: &Args,
    input_file: &mut File,
    output_file: &mut File,
    key: &[u8],
    nonce: &[u8],
) -> Result<()> {
    // create the cipher instance
    let cipher = ChaCha20Poly1305::new(key.into());

    let mut stream_encryptor = stream::EncryptorBE32::from_aead(cipher, nonce.into());
    // reset file location
    input_file.rewind()?;
    let mut buffer = [0u8; 500];
    loop {
        let read_count = input_file.read(&mut buffer)?;
        if read_count == 500 {
            let ciphertext = stream_encryptor
                .encrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Encrypting {}", err))?;
            output_file.write(&ciphertext)?;
        } else {
            let ciphertext = stream_encryptor
                .encrypt_last(&buffer[..read_count])
                .map_err(|err| anyhow!("Encrypting {}", err))?;
            output_file.write(&ciphertext)?;
            break;
        }
    }
    println!("Encrypted {}", args.file.green());
    Ok(())
}

pub fn stream_decrypt(
    args: &Args,
    input_file: &mut File,
    output_file: &mut File,
    key: &[u8],
    nonce: &[u8],
) -> Result<()> {
    // create the cipher instance
    let cipher = ChaCha20Poly1305::new(key.into());

    let mut stream_decryptor = stream::DecryptorBE32::from_aead(cipher, nonce.as_ref().into());
    // reset file location
    input_file.rewind()?;
    let mut buffer = [0u8; 516];
    loop {
        let read_count = input_file.read(&mut buffer)?;
        if read_count == 516 {
            let plaintext = stream_decryptor
                .decrypt_next(buffer.as_slice())
                .map_err(|err| anyhow!("Decrypting {}", err))?;
            output_file.write(&plaintext)?;
        } else if read_count == 0 {
            break;
        }
        let plaintext = stream_decryptor
            .decrypt_last(&buffer[..read_count])
            .map_err(|err| anyhow!("Decrypting {}", err))?;
        output_file.write(&plaintext)?;
        break;
    }
    println!("Decrypted {}", args.file.green());
    Ok(())
}
