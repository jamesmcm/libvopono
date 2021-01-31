use thiserror::Error;

#[derive(Error, Debug)]
pub enum LibVoponoError {
    #[error("failed to add NetFilter rule")]
    NetFilterError(String),
}
