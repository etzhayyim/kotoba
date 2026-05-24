use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("program not found: {0}")]
    ProgramNotFound(String),

    #[error("compile failed: {0}")]
    CompileFailed(#[source] anyhow::Error),

    #[error("instantiate failed: {0}")]
    InstantiateFailed(#[source] anyhow::Error),

    #[error("execution trapped: {0}")]
    Trap(String),

    #[error("guest returned error: {0}")]
    GuestError(String),

    #[error("context decode failed: {0}")]
    ContextDecode(#[source] anyhow::Error),

    #[error("host call failed: {0}")]
    HostCall(#[source] anyhow::Error),

    #[error("gas limit exceeded (limit={limit})")]
    GasExceeded { limit: u64 },
}
