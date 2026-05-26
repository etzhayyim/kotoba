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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_not_found_display() {
        let e = RuntimeError::ProgramNotFound("cid123".to_string());
        assert!(e.to_string().contains("cid123"));
    }

    #[test]
    fn trap_display() {
        let e = RuntimeError::Trap("stack overflow".to_string());
        assert!(e.to_string().contains("stack overflow"));
    }

    #[test]
    fn guest_error_display() {
        let e = RuntimeError::GuestError("out of gas".to_string());
        assert!(e.to_string().contains("out of gas"));
    }

    #[test]
    fn gas_exceeded_display_contains_limit() {
        let e = RuntimeError::GasExceeded { limit: 10_000_000 };
        let s = e.to_string();
        assert!(s.contains("10000000") || s.contains("10_000_000"), "got: {s}");
    }
}
