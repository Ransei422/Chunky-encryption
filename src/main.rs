use chunky_encryption::*;
use clap::Parser;




#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Cli {
    /// Path to the master key file
    #[arg(short, long)]
    pub key: String,

    /// Path to the input file or directory
    #[arg(short, long)]
    pub input: String,

    /// Path to the output file or directory
    #[arg(short, long)]
    pub output: String,

    /// Delete all files after decryption
    #[arg(short, long)]
    pub clear: bool,

    /// Path to the metadata file
    #[arg(short, long)]
    pub meta: String,

    /// Set this flag to encrypt (omit for decrypt)
    #[arg(short, long)]
    pub encrypt: bool,

    /// Set this flag if input is a directory
    #[arg(short, long)]
    pub directory: bool,
}



fn main() {
    let cli = Cli::parse();
    let master_key: Vec<u8> = if cli.encrypt {
        match generate_and_save_master_key(&cli.key) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("[ ERR ] Failed to generate master key: {e}");
                std::process::exit(1);
            }
        }
    } else {
        if std::path::Path::new(&cli.key).exists() {
            match std::fs::read(&cli.key) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("[ ERR ] Failed to read master key: {e}");
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("[ ERR ] Master key not found: {}", &cli.key);
            std::process::exit(1);
        }
    };


    if master_key.len() != 32 {
        eprintln!("[ ERR ] Master Key must be just 32 bytes long.");
        std::process::exit(1);
    }
    

    if cli.encrypt {
        if let Err(e) = create_output_dir(&cli.output) {
            eprintln!("[ ERR ] Failed to create output directory: {e}");
            std::process::exit(1);
        }

        if cli.directory {
            if let Err(e) = archive_and_encrypt_dir(&cli.input, &cli.output, &cli.meta, &master_key) {
                eprintln!("[ ERR ] Failed to encrypt directory: {e}");
                std::process::exit(1);
            }
            println!("[ INF ] Encryption (directory) complete.");
        } else {
            if let Err(e) = encrypt_file(&cli.input, &cli.output, &cli.meta, &master_key) {
                eprintln!("[ ERR ] Failed to encrypt file: {e}");
                std::process::exit(1);
            }
            println!("[ INF ] Encryption (file) complete.");
        }
    } else {
        if let Err(e) = decrypt_file(&cli.input, &cli.meta, &cli.output, &master_key, cli.clear, &cli.key) {
            eprintln!("[ ERR ] Failed to decrypt file: {e}");
            std::process::exit(1);
        }
        println!("[ INF ] Decryption complete.");
    }

}
