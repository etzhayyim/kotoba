use crate::cid::KotobaCid;

pub const GRAPH_PUBLIC_NAME: &str = "kotoba://graph/public";
pub const GRAPH_AUTHED_NAME: &str = "kotoba://graph/authed";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphVisibility {
    Public,
    Authenticated,
    Private { owner_did: String },
}

pub struct NamedGraph {
    pub name:       String,
    pub cid:        KotobaCid,
    pub visibility: GraphVisibility,
}

impl NamedGraph {
    pub fn new(name: &str, visibility: GraphVisibility) -> Self {
        Self {
            name:       name.to_string(),
            cid:        KotobaCid::from_bytes(name.as_bytes()),
            visibility,
        }
    }

    pub fn public() -> Self {
        Self::new(GRAPH_PUBLIC_NAME, GraphVisibility::Public)
    }

    pub fn authenticated() -> Self {
        Self::new(GRAPH_AUTHED_NAME, GraphVisibility::Authenticated)
    }

    pub fn private_for(did: &str) -> Self {
        let name = format!("kotoba://graph/private/{did}");
        Self::new(&name, GraphVisibility::Private { owner_did: did.to_string() })
    }
}

/// Classify a graph by name convention.
/// The caller must provide the original name (stored at write time).
/// Unknown graphs default to `Authenticated` (safe default).
pub fn classify(name: &str) -> GraphVisibility {
    if name == GRAPH_PUBLIC_NAME {
        GraphVisibility::Public
    } else if name == GRAPH_AUTHED_NAME {
        GraphVisibility::Authenticated
    } else if let Some(did) = name.strip_prefix("kotoba://graph/private/") {
        GraphVisibility::Private { owner_did: did.to_string() }
    } else {
        // Unknown graphs default to Authenticated
        GraphVisibility::Authenticated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_graph_cid_is_stable() {
        let g1 = NamedGraph::public();
        let g2 = NamedGraph::public();
        assert_eq!(g1.cid, g2.cid);
        assert_eq!(g1.name, GRAPH_PUBLIC_NAME);
    }

    #[test]
    fn authed_graph_cid_differs_from_public() {
        let pub_g  = NamedGraph::public();
        let auth_g = NamedGraph::authenticated();
        assert_ne!(pub_g.cid, auth_g.cid);
    }

    #[test]
    fn private_graph_encodes_did() {
        let did = "did:erc725:gftd:260425:0xdeadbeef";
        let g = NamedGraph::private_for(did);
        assert_eq!(g.name, format!("kotoba://graph/private/{did}"));
        assert!(matches!(g.visibility, GraphVisibility::Private { owner_did } if owner_did == did));
    }

    #[test]
    fn classify_public() {
        assert_eq!(classify(GRAPH_PUBLIC_NAME), GraphVisibility::Public);
    }

    #[test]
    fn classify_authed() {
        assert_eq!(classify(GRAPH_AUTHED_NAME), GraphVisibility::Authenticated);
    }

    #[test]
    fn classify_private() {
        let did = "did:erc725:gftd:260425:0xabc123";
        let name = format!("kotoba://graph/private/{did}");
        assert_eq!(
            classify(&name),
            GraphVisibility::Private { owner_did: did.to_string() }
        );
    }

    #[test]
    fn classify_unknown_defaults_to_authenticated() {
        assert_eq!(classify("kotoba://graph/unknown-custom"), GraphVisibility::Authenticated);
        assert_eq!(classify("some-arbitrary-string"), GraphVisibility::Authenticated);
    }
}
