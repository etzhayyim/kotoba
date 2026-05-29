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
        assert!(
            s.contains("10000000") || s.contains("10_000_000"),
            "got: {s}"
        );
    }

    #[test]
    fn compile_failed_display() {
        let e = RuntimeError::CompileFailed(anyhow::anyhow!("bad wasm magic bytes"));
        let s = e.to_string();
        assert!(s.contains("compile"), "got: {s}");
    }

    #[test]
    fn instantiate_failed_display() {
        let e = RuntimeError::InstantiateFailed(anyhow::anyhow!("missing import"));
        let s = e.to_string();
        assert!(s.contains("instantiate"), "got: {s}");
    }

    #[test]
    fn context_decode_display() {
        let e = RuntimeError::ContextDecode(anyhow::anyhow!("unexpected eof"));
        let s = e.to_string();
        assert!(s.contains("context") || s.contains("decode"), "got: {s}");
    }

    #[test]
    fn host_call_display() {
        let e = RuntimeError::HostCall(anyhow::anyhow!("host fn returned error"));
        let s = e.to_string();
        assert!(s.contains("host"), "got: {s}");
    }

    #[test]
    fn all_variants_have_distinct_display_prefixes() {
        let variants: Vec<String> = vec![
            RuntimeError::ProgramNotFound("x".to_string()).to_string(),
            RuntimeError::CompileFailed(anyhow::anyhow!("e")).to_string(),
            RuntimeError::InstantiateFailed(anyhow::anyhow!("e")).to_string(),
            RuntimeError::Trap("e".to_string()).to_string(),
            RuntimeError::GuestError("e".to_string()).to_string(),
            RuntimeError::ContextDecode(anyhow::anyhow!("e")).to_string(),
            RuntimeError::HostCall(anyhow::anyhow!("e")).to_string(),
            RuntimeError::GasExceeded { limit: 1 }.to_string(),
        ];
        // All display strings must be distinct (different prefixes)
        let mut sorted = variants.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            variants.len(),
            "some variants share the same display: {variants:?}"
        );
    }
}
