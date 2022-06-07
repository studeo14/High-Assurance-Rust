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
    path::{Path, PathBuf},
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
    pub file: PathBuf,

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

pub fn process_item(args: &Args, item: &Path) -> Result<()> {
    if item.is_dir() {
        process_directory(args, item)
    } else if item.is_file() {
        process_file(args, item)
    } else {
        Err(anyhow!("{} is neither a path or a file.", item.display()))
    }
}

fn process_directory(args: &Args, directory: &Path) -> Result<()> {
    if !directory.is_dir() {
        Err(anyhow!("Expected dir, got {}", directory.display()))
    } else {
        for item in directory.read_dir()? {
            let i = item?;
            process_item(args, i.path().as_path())?
        }
        Ok(())
    }
}

fn process_file(args: &Args, file: &Path) -> Result<()> {
    if !file.is_file() {
        Err(anyhow!("Expected file, got {}", file.display()))
    } else {
        encrypt_or_decrypt_file(args, file)
    }
}

pub fn encrypt_or_decrypt_file(args: &Args, input_file_name: &Path) -> Result<()> {
    let encrypt = encrypt_or_decrypt(&args, input_file_name)?;

    // If predict only just return
    if args.predict_only {
        return Ok(());
    }

    // read in user arguments
    // Note:
    // Enfore length here
    if args.key.len() != 32 {
        return Err(anyhow!("Key must be 32 characters long",));
    }
    let key = args.key.as_bytes();
    let nonce = args.nonce.as_bytes();

    // Overwrite the existing file check
    let filename = if args.overwrite {
        println!(
            "{}; You are overwriting {}",
            "WARNING".yellow(),
            args.file.to_str().unwrap().red()
        );
        args.file.display().to_string()
    } else {
        if encrypt {
            format!("{}.enc", args.file.display())
        } else {
            format!("{}.denc", args.file.display())
        }
    };

    println!("Writing result to {}", filename.green());

    let file_path = Path::new(&filename);

    // En/Decrypt the file
    if encrypt {
        stream_encrypt(args.file.as_path(), file_path, key, nonce)?;
    } else {
        stream_decrypt(args.file.as_path(), file_path, key, nonce)?;
    }

    Ok(())
}

pub fn encrypt_or_decrypt(args: &Args, input_file_name: &Path) -> Result<bool> {
    let mut input_file = File::options().read(true).open(input_file_name)?;
    let mut buffer = [0u8; 500];
    // Read the first chunk of the file
    let read_count = input_file.read(&mut buffer)?;
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
    input_file_name: &Path,
    output_file_name: &Path,
    key: &[u8],
    nonce: &[u8],
) -> Result<()> {
    let mut input_file = File::options().read(true).open(input_file_name)?;
    let mut output_file = File::options()
        .create(true)
        .truncate(true)
        .write(true)
        .open(output_file_name)?;
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
    println!(
        "Encrypted {}",
        input_file_name.display().to_string().green()
    );
    Ok(())
}

pub fn stream_decrypt(
    input_file_name: &Path,
    output_file_name: &Path,
    key: &[u8],
    nonce: &[u8],
) -> Result<()> {
    let mut input_file = File::options().read(true).open(input_file_name)?;
    let mut output_file = File::options()
        .create(true)
        .truncate(true)
        .write(true)
        .open(output_file_name)?;
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
    println!(
        "Decrypted {}",
        input_file_name.display().to_string().green()
    );
    Ok(())
}
