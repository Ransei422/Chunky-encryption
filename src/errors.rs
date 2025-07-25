
#[allow(dead_code)]
#[derive(Debug)]
pub enum EncryptionErrors {
    FileCreationError,
    FileOpenError,
    DecodeError,
    BufferReadInitialize,
    BufferReadError,
    WritingError,
    ArchiveCreationError,
    CreateCypherError,
    CypherEncryptError,
    CypherDecryptError,
    NonceError,
    DirectoryDeletionError,
    EncodeError,
    FileDeletionError,

}

#[allow(dead_code)]
#[derive(Debug)]
pub struct EncryptionError {
    pub code: EncryptionErrors,
    pub error_msg: String,
}

#[allow(dead_code)]
impl EncryptionError {
    pub fn new(code: EncryptionErrors) -> EncryptionError {
        let err = match code {
            EncryptionErrors::FileCreationError => String::from("→ Not able to create a file"),
            EncryptionErrors::FileOpenError => String::from("→ Not able to open file"),
            EncryptionErrors::DecodeError => String::from("→ Not able to decode file"),
            EncryptionErrors::BufferReadInitialize => String::from("→ Not able to create buffer reader"),
            EncryptionErrors::BufferReadError => String::from("→ Not able to read data from buffer"),
            EncryptionErrors::WritingError => String::from("→ Not able to write data"),
            EncryptionErrors::ArchiveCreationError => String::from("→ Not able to create archive"),
            EncryptionErrors::CreateCypherError => String::from("→ Not able to create cypher from Master Key"),
            EncryptionErrors::CypherEncryptError => String::from("→ Not able to encrypt file with current Cypher"),
            EncryptionErrors::CypherDecryptError => String::from("→ Not able to decrypt file with current Cypher"),
            EncryptionErrors::NonceError => String::from("→ Not enought data to decode Nonce data from file"),
            EncryptionErrors::DirectoryDeletionError => String::from("→ Not able to delete directory with encrypted data"),
            EncryptionErrors::EncodeError => String::from("→ Not able to encode keychain into vector"),
            EncryptionErrors::FileDeletionError => String::from("→ Not able to delete unencrypted temporary .tar file")
        };

        EncryptionError {
            code: code,
            error_msg:err
        }
    }
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.error_msg)
    }
}