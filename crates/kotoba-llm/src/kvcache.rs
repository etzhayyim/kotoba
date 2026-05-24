use kotoba_core::cid::KotobaCid;
use kotoba_kqe::arrangement::Arrangement;
use kotoba_kqe::quad::{Quad, QuadObject};
use kotoba_kqe::delta::Delta;

/// KvCache — attention KV-cache as ephemeral Arrangement
/// session_cid = blake3(CBOR{model_cid, prompt_hash, ts})
/// Each KV pair = Datom: Quad(session, "kv/layer/N/seq/M", kv_tensor_cid)
/// Pregel: KV-cache = vertex state during inference supersteps
pub struct KvCache {
    pub session_cid: KotobaCid,
    pub arrangement: Arrangement,
}

impl KvCache {
    pub fn new(session_cid: KotobaCid) -> Self {
        Self { session_cid, arrangement: Arrangement::new() }
    }

    /// Store KV pair for layer N, sequence position M
    pub fn store_kv(&mut self, graph_cid: KotobaCid, layer: u32, seq: u32, kv_cid: KotobaCid) -> Delta {
        let quad = Quad {
            graph:     graph_cid,
            subject:   self.session_cid.clone(),
            predicate: format!("kv/layer/{layer}/seq/{seq}"),
            object:    QuadObject::Cid(kv_cid),
        };
        self.arrangement.insert(&quad);
        Delta::assert(quad)
    }

    /// Clear cache (Vote to Halt → TTL GC)
    pub fn clear(&mut self) { self.arrangement = Arrangement::new(); }
}
