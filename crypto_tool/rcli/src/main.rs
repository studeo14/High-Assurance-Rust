//! Encryption CLI
//! Author: Steven Frederiksen
//! Derived From: https://highassurance.rs/chp2/cli.html
use anyhow::Result;
use clap::Parser;
use rcli::Args;

fn main() -> Result<()> {
    let args = Args::parse();

    rcli::process_item(&args, args.file.as_path())
}
