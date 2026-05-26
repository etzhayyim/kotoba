/// GossipSub topic ↔ KSE Journal Topic mapping
pub fn gossipsub_topic(kotoba_topic: &str) -> String {
    format!("kotoba/{}", kotoba_topic.trim_start_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_topic_gets_kotoba_prefix() {
        assert_eq!(gossipsub_topic("quad/assert"), "kotoba/quad/assert");
    }

    #[test]
    fn leading_slash_is_stripped() {
        assert_eq!(gossipsub_topic("/quad/assert"), "kotoba/quad/assert");
    }

    #[test]
    fn multiple_leading_slashes_stripped() {
        assert_eq!(gossipsub_topic("//pregel/messages"), "kotoba/pregel/messages");
    }

    #[test]
    fn empty_topic_gives_bare_prefix() {
        assert_eq!(gossipsub_topic(""), "kotoba/");
    }

    #[test]
    fn already_kotoba_prefix_not_doubled() {
        // When callers pass the raw KSE topic name (no leading slash), the result
        // should be exactly one "kotoba/" prefix.
        let t = gossipsub_topic("pregel/messages");
        assert_eq!(t, "kotoba/pregel/messages");
        assert!(!t.contains("kotoba/kotoba/"), "prefix must not be doubled");
    }
}
