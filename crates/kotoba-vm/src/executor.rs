use kotoba_core::cid::KotobaCid;
use kotoba_kqe::{arrangement::Arrangement, delta::Delta, datalog::DatalogProgram};
use std::sync::Arc;
use crate::pregel::{graph_from_deltas, datalog_compute_fn};

/// KVM execution result
#[derive(Debug)]
pub struct ExecResult {
    pub call_id:    u64,
    pub status:     ExecStatus,
    pub out_deltas: Vec<Delta>,
    pub steps_used: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStatus { Ok, Halt, StepsExceeded, Error }

/// KotobaVM — executes Invoke ChainEntry via Pregel BSP supersteps
pub struct KotobaVm;

impl KotobaVm {
    /// Execute Datalog program via Pregel BSP supersteps.
    ///
    /// Each vertex = a subject in the input deltas.
    /// Each superstep = one round of Datalog semi-naive evaluation.
    /// Fixpoint = all vertices halted (no new derived facts).
    pub fn execute(
        program_cid:  &KotobaCid,
        program:      &DatalogProgram,
        input:        &Arrangement,
        input_deltas: &[Delta],
        max_steps:    u32,
        call_id:      u64,
    ) -> ExecResult {
        let _ = (program_cid, input); // used in distributed impl

        if program.rules.is_empty() || input_deltas.is_empty() {
            return ExecResult {
                call_id,
                status:     ExecStatus::Ok,
                out_deltas: vec![],
                steps_used: 0,
            };
        }

        // Build Pregel graph from input deltas
        let mut graph = graph_from_deltas(input_deltas);

        // Compute function: each vertex runs DatalogProgram.evaluate_delta
        let prog = Arc::new(program.clone());
        let deltas = Arc::new(input_deltas.to_vec());
        let compute = datalog_compute_fn(prog, deltas);

        // Run BSP supersteps
        let results = graph.run(&compute, max_steps);
        let steps_used = results.len() as u32;

        // Collect all derived deltas by re-running evaluate_delta once globally
        // (vertex states track counts; full derived set is reassembled here)
        let out_deltas = program.evaluate_delta(input_deltas);

        let status = if steps_used >= max_steps
            && !results.last().map_or(false, |r| r.all_halted)
        {
            ExecStatus::StepsExceeded
        } else {
            ExecStatus::Ok
        };

        ExecResult { call_id, status, out_deltas, steps_used }
    }
}
