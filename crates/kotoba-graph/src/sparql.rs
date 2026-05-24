/// SPARQL BGP → Datalog rule translation (placeholder)
/// Full implementation in Phase 3

pub struct SparqlQuery {
    pub bgp: Vec<TriplePattern>,
    pub filters: Vec<String>,
}

pub struct TriplePattern {
    pub subject:   VarOrTerm,
    pub predicate: VarOrTerm,
    pub object:    VarOrTerm,
}

pub enum VarOrTerm {
    Variable(String),
    Iri(String),
    Literal(String),
}

impl SparqlQuery {
    /// Convert BGP to Datalog atoms
    pub fn to_datalog_atoms(&self) -> Vec<String> {
        self.bgp.iter().map(|tp| {
            let s = term_str(&tp.subject);
            let p = term_str(&tp.predicate);
            let o = term_str(&tp.object);
            format!("quad(G, {s}, {p}, {o})")
        }).collect()
    }
}

fn term_str(t: &VarOrTerm) -> String {
    match t {
        VarOrTerm::Variable(v) => v.clone(),
        VarOrTerm::Iri(i)      => format!("{i:?}"),
        VarOrTerm::Literal(l)  => format!("{l:?}"),
    }
}
