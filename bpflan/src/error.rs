use thiserror::Error;

#[derive(Debug, Error)]
#[error("error")]
pub enum Error {
    #[error("Failed to create interface")]
    InterfaceCreateFailed,
    #[error("aya program error")]
    AyaError,
    #[error("ioctl call failed")]
    IoctlError,
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

impl From<aya::programs::ProgramError> for Error {
    fn from(err: aya::programs::ProgramError) -> Self {
        Self::AyaError
    }
}

impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Self {
        Self::IoctlError
    }
}
