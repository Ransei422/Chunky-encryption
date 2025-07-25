#[derive(Debug,Clone)]
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


#[derive(Debug, Clone)]
pub struct EncryptionError {
    pub code: EncryptionErrors,
    pub error_msg: String,
}


impl EncryptionError {
    pub fn new(code: EncryptionErrors, propagated_error: &str) -> EncryptionError {
        let err = match code {
            EncryptionErrors::FileCreationError => format!("→ Not able to create a file: {propagated_error}"),
            EncryptionErrors::FileOpenError => format!("→ Not able to open a file: {propagated_error}"),
            EncryptionErrors::DecodeError => format!("→ Not able to decode a file: {propagated_error}"),
            EncryptionErrors::BufferReadInitialize => format!("→ Not able to create buffer reader: {propagated_error}"),
            EncryptionErrors::BufferReadError => format!("→ Not able to read data from buffer: {propagated_error}"),
            EncryptionErrors::WritingError => format!("→ Not able to write a data: {propagated_error}"),
            EncryptionErrors::ArchiveCreationError => format!("→ Not able to create an archive: {propagated_error}"),
            EncryptionErrors::CreateCypherError => format!("→ Not able to create cypher from Master Key: {propagated_error}"),
            EncryptionErrors::CypherEncryptError => format!("→ Not able to encrypt file with current Cypher: {propagated_error}"),
            EncryptionErrors::CypherDecryptError => format!("→ Not able to decrypt file with current Cypher: {propagated_error}"),
            EncryptionErrors::NonceError => format!("→ Not enought data to decode Nonce data from file: {propagated_error}"),
            EncryptionErrors::DirectoryDeletionError => format!("→ Not able to delete directory with encrypted data: {propagated_error}"),
            EncryptionErrors::EncodeError => format!("→ Not able to encode keychain into vector: {propagated_error}"),
            EncryptionErrors::FileDeletionError => format!("→ Not able to delete unencrypted temporary .tar file: {propagated_error}"),
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


pub(crate) fn wrap_err<E: ToString>(code: EncryptionErrors) -> impl FnOnce(E) -> EncryptionError {
    move |e| EncryptionError::new(code.clone(), &e.to_string())
}
