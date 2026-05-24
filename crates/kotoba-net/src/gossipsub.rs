/// GossipSub topic ↔ KSE Journal Topic mapping
pub fn gossipsub_topic(kotoba_topic: &str) -> String {
    format!("kotoba/{}", kotoba_topic.trim_start_matches('/'))
}
