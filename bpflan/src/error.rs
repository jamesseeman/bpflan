use thiserror::Error;

#[derive(Debug, Error)]
#[error("error")]
pub enum Error {
    #[error("Failed to create interface")]
    InterfaceCreateFailed,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::InterfaceCreateFailed
    }
}

impl From<rtnetlink::Error> for Error {
    fn from(err: rtnetlink::Error) -> Self {
        Self::InterfaceCreateFailed
    }
}
