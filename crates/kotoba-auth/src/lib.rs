pub mod did_document;
pub mod cacao;
pub mod delegation;
pub mod eth;

pub use did_document::{DidDocument, VerificationMethod, ServiceEndpoint};
pub use cacao::{Cacao, CacaoHeader, CacaoPayload, CacaoSig, CacaoError};
pub use delegation::{DelegationChain, DelegationError};
pub use eth::{eth_address_to_erc725_did, personal_sign_hash, recover_eth_address};
