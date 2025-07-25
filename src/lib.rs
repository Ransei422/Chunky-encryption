use rand::RngCore;
use aes_gcm::aead::rand_core::RngCore as _;
use aes_gcm::{
    Aes256Gcm,
    Key,
    Nonce,
};
use aes_gcm::aead::{
    Aead,
    KeyInit,
    OsRng
};
use bincode::{
    encode_to_vec,
    decode_from_slice,
    config::standard,
    Decode,
    Encode,
};
use std::fs::{
    File,
    remove_dir_all,
    remove_file,
    create_dir_all
};
use std::io::{
    BufReader,
    BufWriter,
    Read,
    Write,
    stdout,
};
use tar::Builder;

use crate::errors::*;
mod errors;


// 1MB chunk size
const CHUNK_SIZE: usize = 1024 * 1024;
const NUANCE_SIZE: usize = 12;


#[derive(Encode, Decode)]
struct ChunkMetadata {
    key: [u8; 32],
    nonce: [u8; 12],
    length: usize,
}


#[derive(Encode, Decode)]
struct EncryptionMetadata {
    chunks: Vec<ChunkMetadata>,
}



/// Encrypt input files to chunks and keychain
pub fn encrypt_file(input_path: &str, output_dir: &str, meta_path: &str, master_key: &[u8]) -> Result<(), EncryptionError> {
    println!("[ INF ] Starting encryption...");

    let mut input = BufReader::new(File::open(input_path)
        .map_err(wrap_err(EncryptionErrors::BufferReadInitialize))?);

    let mut metadata = EncryptionMetadata { chunks: vec![] };
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut index = 0;

    let mut rng = rand::rng();

    loop {
        let n = input.read(&mut buffer)
            .map_err(wrap_err(EncryptionErrors::BufferReadError))?;

        if n == 0 {
            break;
        }

        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce_obj = Nonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(nonce_obj, &buffer[..n])
            .map_err(wrap_err(EncryptionErrors::CypherEncryptError))?;

        let chunk_file = format!("{}/chunk_{:01}.enc", output_dir, index);
        let mut out = BufWriter::new(File::create(&chunk_file)
            .map_err(wrap_err(EncryptionErrors::FileCreationError))?);

        out.write_all(&ciphertext)
            .map_err(wrap_err(EncryptionErrors::WritingError))?;

        metadata.chunks.push(ChunkMetadata {
            key,
            nonce,
            length: n,
        });

        print!("\r[ INF ] Encrypted {}MB", index + 1);
        stdout().flush().expect("[ ERR ] Failed to flush stdout");

        index += 1;
    }
    println!();

    let encoded = encode_to_vec(&metadata, standard())
        .map_err(wrap_err(EncryptionErrors::EncodeError))?;

    let encrypted_metadata = encrypt_metadata(&encoded, master_key)?;

    let mut meta_file = BufWriter::new(File::create(meta_path)
        .map_err(wrap_err(EncryptionErrors::FileCreationError))?);

    meta_file.write_all(&encrypted_metadata)
        .map_err(wrap_err(EncryptionErrors::WritingError))?;

    Ok(())
}



/// Decrypt input files using chunks and keychain
pub fn decrypt_file(encrypted_dir: &str, meta_path: &str, output_path: &str, master_key: &[u8], clear: bool, master_key_path: &str) -> Result<(), EncryptionError> {
    println!("[ INF ] Starting decryption...");

    let config = standard();
    let mut meta_file = File::open(meta_path)
        .map_err(wrap_err(EncryptionErrors::FileOpenError))?;
    let mut encrypted = Vec::new();
    meta_file.read_to_end(&mut encrypted)
        .map_err(wrap_err(EncryptionErrors::BufferReadError))?;

    let decrypted = decrypt_metadata(&encrypted, master_key)?;
    let (metadata, _): (EncryptionMetadata, usize) =
        decode_from_slice::<EncryptionMetadata, _>(&decrypted, config)
            .map_err(wrap_err(EncryptionErrors::DecodeError))?;

    let mut output = BufWriter::new(File::create(output_path)
        .map_err(wrap_err(EncryptionErrors::FileCreationError))?);

    for (i, chunk_meta) in metadata.chunks.iter().enumerate() {
        print!("\r[ INF ] Decrypting chunk {}/{}", i + 1, metadata.chunks.len());
        stdout().flush().expect("[ ERR ] Failed to flush stdout");
        
        let chunk_file = format!("{}/chunk_{:01}.enc", encrypted_dir, i);
        let mut chunk_data = vec![];

        BufReader::new(File::open(&chunk_file)
            .map_err(wrap_err(EncryptionErrors::FileOpenError))?)
            .read_to_end(&mut chunk_data)
            .map_err(wrap_err(EncryptionErrors::BufferReadError))?;

        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&chunk_meta.key));
        let nonce_obj = Nonce::from_slice(&chunk_meta.nonce);

        let plaintext = cipher
            .decrypt(nonce_obj, chunk_data.as_ref())
            .map_err(wrap_err(EncryptionErrors::CypherDecryptError))?;

        output.write_all(&plaintext[..chunk_meta.length]).map_err(wrap_err(EncryptionErrors::WritingError))?;
    }
    println!();

    if clear {
        remove_dir_all(encrypted_dir).map_err(wrap_err(EncryptionErrors::DirectoryDeletionError))?;
        remove_file(meta_path).map_err(wrap_err(EncryptionErrors::FileDeletionError))?;
        remove_file(master_key_path).map_err(wrap_err(EncryptionErrors::FileDeletionError))?;
    }

    Ok(())
}



/// Encrypt keychain with AES256
fn encrypt_metadata(data: &[u8], master_key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(wrap_err(EncryptionErrors::CreateCypherError))?;

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let nonce_obj = Nonce::from_slice(&nonce);

    let ciphertext = cipher.encrypt(nonce_obj, data)
        .map_err(wrap_err(EncryptionErrors::CypherEncryptError))?;

    let mut out = nonce.to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}



/// Decrypt keychain with AES256
fn decrypt_metadata(encrypted: &[u8], master_key: &[u8]) -> Result<Vec<u8>, EncryptionError> {
    if encrypted.len() < NUANCE_SIZE {
        return Err(EncryptionError::new(EncryptionErrors::NonceError, "Nonce too short"));
    }

    let (nonce_bytes, ciphertext) = encrypted.split_at(NUANCE_SIZE);

    let cipher = Aes256Gcm::new_from_slice(master_key)
        .map_err(wrap_err(EncryptionErrors::CreateCypherError))?;

    let nonce_obj = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce_obj, ciphertext)
        .map_err(wrap_err(EncryptionErrors::CypherDecryptError))
}



/// Create one archive from all files in directory, encrypt&chop&save it and remove no-encrypted archive
pub fn archive_and_encrypt_dir(input_dir: &str, output_dir: &str, meta_path: &str, master_key: &[u8]) -> Result<(), EncryptionError> {
    let archive_path = format!("{}/archive.tar", output_dir);
    let tar_file = File::create(&archive_path)
        .map_err(wrap_err(EncryptionErrors::FileCreationError))?;

       let mut tar_builder = Builder::new(tar_file);
        tar_builder
            .append_dir_all(".", input_dir)
            .map_err(wrap_err(EncryptionErrors::ArchiveCreationError))?;

        tar_builder
            .into_inner()
            .map_err(wrap_err(EncryptionErrors::ArchiveCreationError))?;

    encrypt_file(&archive_path, output_dir, meta_path, master_key)?;

    remove_file(&archive_path)
        .map_err(wrap_err(EncryptionErrors::FileCreationError))?;

    Ok(())
}



/// Generate a semi-random master key to encrypt keychain
pub fn generate_and_save_master_key(key_path: &str) -> Result<Vec<u8>, EncryptionError> {
    let mut key: [u8; 32] = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let mut file = File::create(key_path)
        .map_err(wrap_err(EncryptionErrors::FileCreationError))?;

    file.write_all(&key)
        .map_err(wrap_err(EncryptionErrors::WritingError))?;

    Ok(key.into())
}



/// Create a directory for outputed chunk files
pub fn create_output_dir(path: &str) -> Result<(), EncryptionError> {
    create_dir_all(path).map_err(wrap_err(EncryptionErrors::DirectoryCreationError))
}