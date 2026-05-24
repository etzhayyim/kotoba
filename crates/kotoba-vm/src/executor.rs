use kotoba_core::cid::KotobaCid;
use kotoba_kqe::{arrangement::Arrangement, delta::Delta, datalog::DatalogProgram};

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

/// KotobaVM — executes Invoke ChainEntry (Pregel Phase 2)
pub struct KotobaVm;

impl KotobaVm {
    /// Execute Datalog program against Arrangement input (bounded by max_steps)
    pub fn execute(
        program_cid: &KotobaCid,
        program: &DatalogProgram,
        input: &Arrangement,
        input_deltas: &[Delta],
        max_steps: u32,
        call_id: u64,
    ) -> ExecResult {
        let mut steps = 0u32;
        let mut out_deltas = Vec::new();

        // Phase 2: Datalog incremental evaluation
        // Each rule application = 1 step
        for _rule in &program.rules {
            if steps >= max_steps {
                return ExecResult {
                    call_id,
                    status: ExecStatus::StepsExceeded,
                    out_deltas,
                    steps_used: steps,
                };
            }
            let derived = program.evaluate_delta(input_deltas);
            out_deltas.extend(derived);
            steps += 1;
        }

        let _ = input; // used for binding in full impl
        let _ = program_cid;

        ExecResult { call_id, status: ExecStatus::Ok, out_deltas, steps_used: steps }
    }
}
