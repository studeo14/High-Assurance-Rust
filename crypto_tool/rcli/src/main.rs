//! Encryption CLI
//! Author: Steven Frederiksen
//! Derived From: https://highassurance.rs/chp2/cli.html
use anyhow::{anyhow, Result};
use clap::Parser;
use colored::Colorize;
use rcli::{stream_encrypt, Args, stream_decrypt};
use std::fs::File;


fn main() -> Result<()> {
    let args = Args::parse();

    // Open the file for read/write
    let mut input_file = File::options().read(true).open(&args.file)?;

    let encrypt = rcli::encrypt_or_decrypt(&args, &mut input_file)?;

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
            args.file.red()
        );
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
        stream_encrypt(&args, &mut input_file, &mut output_file, key, nonce)?;
    } else {
        stream_decrypt(&args, &mut input_file, &mut output_file, key, nonce)?;
    }

    Ok(())
}
