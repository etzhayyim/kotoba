use crate::arrangement::Arrangement;
use crate::delta::Delta;
use crate::datalog::DatalogProgram;

/// MaterializedView — incrementally maintained Datalog query result
/// = Pregel Aggregator (cross-vertex Arrangement)
pub struct MaterializedView {
    pub name:    String,
    pub program: DatalogProgram,
    pub state:   Arrangement,
}

impl MaterializedView {
    pub fn new(name: impl Into<String>, program: DatalogProgram) -> Self {
        Self { name: name.into(), program, state: Arrangement::new() }
    }

    /// Pregel Phase 2: apply incoming Deltas, produce out_deltas
    pub fn apply(&mut self, deltas: &[Delta]) -> Vec<Delta> {
        self.state.apply(deltas);
        self.program.evaluate_delta(deltas)
    }
}
