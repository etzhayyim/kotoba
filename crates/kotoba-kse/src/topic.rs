/// Topic — hierarchical address (clean room, inspired by NATS subjects)
/// Separator: '/', wildcards: '*' (one segment), '>' (rest)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Topic(pub String);

impl Topic {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn segments(&self) -> Vec<&str> {
        self.0.split('/').filter(|s| !s.is_empty()).collect()
    }

    pub fn matches(&self, pattern: &TopicPattern) -> bool {
        let segs = self.segments();
        let pats = pattern.0.segments();
        let mut si = 0;
        for (pi, p) in pats.iter().enumerate() {
            if *p == ">" {
                return true;
            }
            if si >= segs.len() {
                return false;
            }
            if *p != "*" && *p != segs[si] {
                return false;
            }
            si += 1;
            if pi == pats.len() - 1 && si != segs.len() {
                return false;
            }
        }
        si == segs.len()
    }

    /// SPO quad topic: /kotoba/quad/{graph}/{subject}/{predicate}/{object}
    pub fn quad_spo(graph: &str, subject: &str, predicate: &str, object: &str) -> Self {
        Self(format!(
            "/kotoba/quad/{graph}/{subject}/{predicate}/{object}"
        ))
    }

    /// POS index topic: /kotoba/pos/{graph}/{predicate}/{object}/{subject}
    pub fn quad_pos(graph: &str, predicate: &str, object: &str, subject: &str) -> Self {
        Self(format!(
            "/kotoba/pos/{graph}/{predicate}/{object}/{subject}"
        ))
    }

    /// PSO index topic: /kotoba/pso/{graph}/{predicate}/{subject}/{object}  (AEVT pub/sub)
    pub fn quad_pso(graph: &str, predicate: &str, subject: &str, object: &str) -> Self {
        Self(format!(
            "/kotoba/pso/{graph}/{predicate}/{subject}/{object}"
        ))
    }

    /// OSP index topic: /kotoba/osp/{graph}/{object}/{subject}/{predicate}
    pub fn quad_osp(graph: &str, object: &str, subject: &str, predicate: &str) -> Self {
        Self(format!(
            "/kotoba/osp/{graph}/{object}/{subject}/{predicate}"
        ))
    }

    /// Commit topic: /kotoba/commit/{graph}
    pub fn commit(graph: &str) -> Self {
        Self(format!("/kotoba/commit/{graph}"))
    }
}

#[derive(Debug, Clone)]
pub struct TopicPattern(pub Topic);

impl TopicPattern {
    pub fn new(s: impl Into<String>) -> Self {
        Self(Topic::new(s))
    }
    /// All quads in a graph: /kotoba/quad/{graph}/>
    pub fn all_quads(graph: &str) -> Self {
        Self::new(format!("/kotoba/quad/{graph}/>"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Topic {
        Topic::new(s)
    }
    fn p(s: &str) -> TopicPattern {
        TopicPattern::new(s)
    }

    #[test]
    fn exact_match() {
        assert!(t("a/b/c").matches(&p("a/b/c")));
    }

    #[test]
    fn exact_mismatch() {
        assert!(!t("a/b/c").matches(&p("a/b/x")));
    }

    #[test]
    fn single_wildcard_matches_one_segment() {
        assert!(t("a/b/c").matches(&p("a/*/c")));
        assert!(!t("a/b/c/d").matches(&p("a/*/c")));
    }

    #[test]
    fn rest_wildcard_matches_any_suffix() {
        assert!(t("a/b/c/d").matches(&p("a/>")));
        assert!(t("a/b").matches(&p("a/>")));
    }

    #[test]
    fn all_quads_pattern_matches_quad_topic() {
        let graph = "g1";
        let topic = Topic::quad_spo(graph, "s", "pred", "obj");
        let pat = TopicPattern::all_quads(graph);
        assert!(topic.matches(&pat));
    }

    #[test]
    fn all_quads_pattern_does_not_match_other_graph() {
        let topic = Topic::quad_spo("g1", "s", "pred", "obj");
        let pat = TopicPattern::all_quads("g2");
        assert!(!topic.matches(&pat));
    }

    #[test]
    fn segments_filters_empty() {
        let topic = Topic::new("/a//b/");
        let segs = topic.segments();
        assert_eq!(segs, vec!["a", "b"]);
    }

    #[test]
    fn commit_topic_format() {
        let t = Topic::commit("mygraph");
        assert_eq!(t.0, "/kotoba/commit/mygraph");
    }

    #[test]
    fn quad_index_topics_differ() {
        let spo = Topic::quad_spo("g", "s", "p", "o");
        let pos = Topic::quad_pos("g", "p", "o", "s");
        let pso = Topic::quad_pso("g", "p", "s", "o");
        let osp = Topic::quad_osp("g", "o", "s", "p");
        // All four are distinct
        assert_ne!(spo.0, pos.0);
        assert_ne!(spo.0, pso.0);
        assert_ne!(spo.0, osp.0);
    }

    #[test]
    fn bare_rest_wildcard_matches_any_topic() {
        // Pattern ">" alone (single segment) should match anything due to early return
        assert!(t("a").matches(&p(">")));
        assert!(t("a/b/c/d/e").matches(&p(">")));
    }

    #[test]
    fn pattern_longer_than_topic_does_not_match() {
        // topic has 2 segments, pattern has 3 — can't match
        assert!(!t("a/b").matches(&p("a/b/c")));
    }

    #[test]
    fn topic_shorter_than_pattern_does_not_match() {
        // topic has 3 segments, pattern has 4
        assert!(!t("a/b/c").matches(&p("a/b/c/d")));
    }

    #[test]
    fn single_wildcard_does_not_match_multiple_segments() {
        // * matches exactly one segment, not two
        assert!(!t("a/b/c").matches(&p("a/*")));
    }

    #[test]
    fn rest_wildcard_at_start_matches_everything() {
        assert!(t("x/y/z").matches(&p(">")));
    }

    #[test]
    fn exact_single_segment_match() {
        assert!(t("hello").matches(&p("hello")));
        assert!(!t("hello").matches(&p("world")));
    }
}
