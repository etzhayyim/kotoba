/// Datalog rule layer (placeholder — full semi-naive evaluation in Phase 4)
/// Monotone semantics: facts only grow via Delta(+1), shrink via Delta(-1)
/// Stratified negation: PTIME complete, halting guaranteed

#[derive(Debug, Clone)]
pub struct DatalogRule {
    pub head: Atom,
    pub body: Vec<BodyLiteral>,
}

#[derive(Debug, Clone)]
pub struct Atom {
    pub relation: String,
    pub args: Vec<Term>,
}

#[derive(Debug, Clone)]
pub enum BodyLiteral {
    Positive(Atom),
    Negative(Atom),  // stratified negation only
    Comparison(Term, CmpOp, Term),
}

#[derive(Debug, Clone)]
pub enum Term {
    Variable(String),
    Constant(String),
}

#[derive(Debug, Clone, Copy)]
pub enum CmpOp { Eq, Ne, Lt, Le, Gt, Ge }

#[derive(Debug, Default, Clone)]
pub struct DatalogProgram {
    pub rules: Vec<DatalogRule>,
}

impl DatalogProgram {
    pub fn new() -> Self { Self::default() }

    pub fn add_rule(&mut self, rule: DatalogRule) { self.rules.push(rule); }

    /// Incremental evaluation: apply Delta batch → produce out_deltas
    /// Full semi-naive implementation in Phase 4
    pub fn evaluate_delta(&self, _deltas: &[crate::delta::Delta]) -> Vec<crate::delta::Delta> {
        // Placeholder: return empty (no derived facts yet)
        vec![]
    }
}
