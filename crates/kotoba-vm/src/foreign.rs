// Re-export from kotoba-core to avoid a cyclic dependency
// (kotoba-llm → kotoba-core::foreign, kotoba-vm → kotoba-core::foreign)
pub use kotoba_core::foreign::{ForeignBridge, ForeignCall, ForeignCallType, ForeignError};
