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
        assert_eq!(
            gossipsub_topic("//pregel/messages"),
            "kotoba/pregel/messages"
        );
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

    #[test]
    fn deeply_nested_topic_preserves_all_segments() {
        let t = gossipsub_topic("a/b/c/d/e");
        assert_eq!(t, "kotoba/a/b/c/d/e");
    }

    #[test]
    fn single_segment_topic() {
        assert_eq!(gossipsub_topic("hello"), "kotoba/hello");
    }

    #[test]
    fn topic_with_only_slash() {
        // A single slash → strip it → bare prefix
        assert_eq!(gossipsub_topic("/"), "kotoba/");
    }

    #[test]
    fn topic_with_numbers_and_hyphens() {
        assert_eq!(
            gossipsub_topic("layer-3/block-42"),
            "kotoba/layer-3/block-42"
        );
    }

    #[test]
    fn topic_result_always_starts_with_kotoba_slash() {
        let inputs = ["foo", "/foo", "//foo", "", "a/b/c"];
        for input in inputs {
            let result = gossipsub_topic(input);
            assert!(
                result.starts_with("kotoba/"),
                "result should start with 'kotoba/': got '{result}' for input '{input}'"
            );
        }
    }

    #[test]
    fn trailing_slash_preserved() {
        assert_eq!(gossipsub_topic("topic/"), "kotoba/topic/");
    }
}
