/// Topic — hierarchical address (clean room, inspired by NATS subjects)
/// Separator: '/', wildcards: '*' (one segment), '>' (rest)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Topic(pub String);

impl Topic {
    pub fn new(s: impl Into<String>) -> Self { Self(s.into()) }

    pub fn segments(&self) -> Vec<&str> {
        self.0.split('/').filter(|s| !s.is_empty()).collect()
    }

    pub fn matches(&self, pattern: &TopicPattern) -> bool {
        let segs = self.segments();
        let pats = pattern.0.segments();
        let mut si = 0;
        for (pi, p) in pats.iter().enumerate() {
            if *p == ">" { return true; }
            if si >= segs.len() { return false; }
            if *p != "*" && *p != segs[si] { return false; }
            si += 1;
            if pi == pats.len() - 1 && si != segs.len() { return false; }
        }
        si == segs.len()
    }

    /// SPO quad topic: /kotoba/quad/{graph}/{subject}/{predicate}/{object}
    pub fn quad_spo(graph: &str, subject: &str, predicate: &str, object: &str) -> Self {
        Self(format!("/kotoba/quad/{graph}/{subject}/{predicate}/{object}"))
    }

    /// POS index topic: /kotoba/pos/{graph}/{predicate}/{object}/{subject}
    pub fn quad_pos(graph: &str, predicate: &str, object: &str, subject: &str) -> Self {
        Self(format!("/kotoba/pos/{graph}/{predicate}/{object}/{subject}"))
    }

    /// OSP index topic: /kotoba/osp/{graph}/{object}/{subject}/{predicate}
    pub fn quad_osp(graph: &str, object: &str, subject: &str, predicate: &str) -> Self {
        Self(format!("/kotoba/osp/{graph}/{object}/{subject}/{predicate}"))
    }

    /// Commit topic: /kotoba/commit/{graph}
    pub fn commit(graph: &str) -> Self {
        Self(format!("/kotoba/commit/{graph}"))
    }
}

#[derive(Debug, Clone)]
pub struct TopicPattern(pub Topic);

impl TopicPattern {
    pub fn new(s: impl Into<String>) -> Self { Self(Topic::new(s)) }
    /// All quads in a graph: /kotoba/quad/{graph}/>
    pub fn all_quads(graph: &str) -> Self {
        Self::new(format!("/kotoba/quad/{graph}/>"))
    }
}
