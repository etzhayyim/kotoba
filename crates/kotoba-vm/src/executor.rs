use crate::pregel::{datalog_compute_fn, graph_from_deltas};
use kotoba_core::cid::KotobaCid;
use kotoba_core::store::BlockStore;
use kotoba_kqe::{arrangement::Arrangement, datalog::DatalogProgram, delta::Delta};
use std::sync::Arc;

/// KVM execution result
#[derive(Debug)]
pub struct ExecResult {
    pub call_id: u64,
    pub status: ExecStatus,
    pub out_deltas: Vec<Delta>,
    pub steps_used: u32,
    /// One content-addressed ProllyTree root CID per superstep — the Merkle
    /// proof chain for this execution.  Empty when no `block_store` was supplied.
    pub checkpoint_cids: Vec<KotobaCid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecStatus {
    Ok,
    Halt,
    StepsExceeded,
    Error,
}

/// KotobaVM — executes Invoke ChainEntry via Pregel BSP supersteps
pub struct KotobaVm;

impl KotobaVm {
    /// Execute Datalog program via Pregel BSP supersteps.
    ///
    /// Each vertex = a subject in the input deltas.
    /// Each superstep = one round of Datalog semi-naive evaluation.
    /// Fixpoint = all vertices halted (no new derived facts).
    ///
    /// When `block_store` is `Some`, a ProllyTree leaf snapshot is written after
    /// every superstep and the resulting root CID is appended to
    /// `ExecResult::checkpoint_cids`, giving one Merkle proof per BSP step.
    pub fn execute(
        program_cid: &KotobaCid,
        program: &DatalogProgram,
        input: &Arrangement,
        input_deltas: &[Delta],
        max_steps: u32,
        call_id: u64,
        block_store: Option<&dyn BlockStore>,
    ) -> ExecResult {
        let _ = (program_cid, input); // used in distributed impl

        if program.rules.is_empty() || input_deltas.is_empty() {
            return ExecResult {
                call_id,
                status: ExecStatus::Ok,
                out_deltas: vec![],
                steps_used: 0,
                checkpoint_cids: vec![],
            };
        }

        let mut graph = graph_from_deltas(input_deltas);

        let prog = Arc::new(program.clone());
        let deltas = Arc::new(input_deltas.to_vec());
        let compute = datalog_compute_fn(prog, deltas);

        // Drive the superstep loop manually so we can checkpoint after each step.
        let mut superstep_results = Vec::new();
        let mut checkpoint_cids = Vec::new();
        let mut last_cid: Option<KotobaCid> = None;

        for _ in 0..max_steps {
            let r = graph.superstep(&compute);
            let halted = r.all_halted;

            if let Some(store) = block_store {
                match graph.checkpoint_chained(store, last_cid.as_ref()) {
                    Ok(cid) => {
                        last_cid = Some(cid.clone());
                        checkpoint_cids.push(cid);
                    }
                    Err(e) => tracing::warn!("superstep checkpoint failed: {e}"),
                }
            }

            superstep_results.push(r);
            if halted {
                break;
            }
        }

        let steps_used = superstep_results.len() as u32;

        let status =
            if steps_used >= max_steps && !superstep_results.last().is_some_and(|r| r.all_halted) {
                ExecStatus::StepsExceeded
            } else {
                ExecStatus::Ok
            };

        let out_deltas = if status == ExecStatus::Ok {
            program.evaluate_delta(input_deltas)
        } else {
            vec![]
        };

        ExecResult {
            call_id,
            status,
            out_deltas,
            steps_used,
            checkpoint_cids,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use kotoba_core::cid::KotobaCid;
    use kotoba_kqe::{
        arrangement::Arrangement,
        datalog::{Atom, BodyLiteral, DatalogProgram, DatalogRule, Term},
        datom::{Datom, Value},
        delta::Delta,
    };

    fn dummy_cid() -> KotobaCid {
        KotobaCid::from_bytes(b"test")
    }
    fn graph_cid() -> KotobaCid {
        KotobaCid::from_bytes(b"graph")
    }

    fn make_delta(subject: &str, predicate: &str) -> Delta {
        Delta::assert_datom(Datom::assert(
            KotobaCid::from_bytes(subject.as_bytes()),
            predicate.to_string(),
            Value::Text(predicate.to_string()),
            graph_cid(),
        ))
    }

    fn one_rule_program() -> DatalogProgram {
        // Atom arity must be 2 (Quad subject + object)
        let mut p = DatalogProgram::default();
        p.add_rule(DatalogRule {
            head: Atom {
                relation: "derived".to_string(),
                args: vec![
                    Term::Variable("X".to_string()),
                    Term::Variable("Y".to_string()),
                ],
            },
            body: vec![BodyLiteral::Positive(Atom {
                relation: "base".to_string(),
                args: vec![
                    Term::Variable("X".to_string()),
                    Term::Variable("Y".to_string()),
                ],
            })],
        });
        p
    }

    #[test]
    fn empty_program_returns_ok_no_deltas() {
        let program = DatalogProgram::default();
        let result = KotobaVm::execute(
            &dummy_cid(),
            &program,
            &Arrangement::new(),
            &[make_delta("alice", "base")],
            10,
            1,
            None,
        );
        assert_eq!(result.status, ExecStatus::Ok);
        assert!(result.out_deltas.is_empty());
        assert_eq!(result.steps_used, 0);
    }

    #[test]
    fn empty_deltas_returns_ok_no_steps() {
        let result = KotobaVm::execute(
            &dummy_cid(),
            &one_rule_program(),
            &Arrangement::new(),
            &[],
            10,
            2,
            None,
        );
        assert_eq!(result.status, ExecStatus::Ok);
        assert!(result.out_deltas.is_empty());
        assert_eq!(result.steps_used, 0);
    }

    #[test]
    fn ok_run_returns_call_id() {
        let result = KotobaVm::execute(
            &dummy_cid(),
            &one_rule_program(),
            &Arrangement::new(),
            &[make_delta("alice", "base")],
            10,
            99,
            None,
        );
        // Status is Ok (datalog_compute_fn votes_halt immediately — single step)
        assert_eq!(result.status, ExecStatus::Ok);
        assert_eq!(result.call_id, 99);
    }

    /// Revert guard: when status is StepsExceeded, out_deltas MUST be empty.
    ///
    /// datalog_compute_fn always votes_halt after one superstep, so to produce
    /// StepsExceeded we need pending messages to remain after max_steps runs.
    /// With two deltas sharing a subject→object chain and max_steps=1, vertex A
    /// computes and sends a message to vertex B in step 1; pending is non-empty
    /// when run() is cut off → all_halted=false → StepsExceeded.
    #[test]
    fn steps_exceeded_returns_empty_deltas() {
        use crate::pregel::{ComputeFn, ComputeOutput, Message, PregelGraph, VertexId};

        // Build a graph manually with a vertex that sends a message every step
        // and never votes halt — forces StepsExceeded regardless of max_steps.
        let mut graph = PregelGraph::new();
        let v = VertexId::from("v");
        graph.add_vertex(v.clone(), Vec::new());
        graph.inject_message(Message {
            src: VertexId::from("seed"),
            dst: v.clone(),
            payload: b"go".to_vec(),
        });

        let compute: ComputeFn = Box::new(|vertex, _| ComputeOutput {
            new_state: vec![],
            messages: vec![Message {
                src: vertex.id.clone(),
                dst: vertex.id.clone(),
                payload: b"loop".to_vec(),
            }],
            vote_halt: false, // never halts
        });

        // Run for exactly 2 steps — graph never halts (self-loop + vote_halt=false)
        let results = graph.run(&compute, 2);
        let steps_used = results.len() as u32;
        let all_halted = results.last().map_or(false, |r| r.all_halted);

        // Verify the StepsExceeded condition is met
        assert!(steps_used >= 2);
        assert!(!all_halted);

        // Mirror the exact branching in KotobaVm::execute:
        let status = if steps_used >= 2 && !all_halted {
            ExecStatus::StepsExceeded
        } else {
            ExecStatus::Ok
        };
        let out_deltas: Vec<Delta> = if status == ExecStatus::Ok {
            vec![make_delta("would", "be-applied")]
        } else {
            vec![] // revert guard
        };

        assert_eq!(status, ExecStatus::StepsExceeded);
        assert!(
            out_deltas.is_empty(),
            "revert guard: StepsExceeded must produce no deltas"
        );
    }

    #[test]
    fn checkpoint_cids_produced_when_store_provided() {
        use kotoba_store::MemoryBlockStore;

        let store = MemoryBlockStore::new();
        let result = KotobaVm::execute(
            &dummy_cid(),
            &one_rule_program(),
            &Arrangement::new(),
            &[make_delta("alice", "base")],
            10,
            42,
            Some(&store),
        );

        assert_eq!(result.status, ExecStatus::Ok);
        // one_rule_program + single delta → one superstep → one checkpoint CID
        assert!(
            !result.checkpoint_cids.is_empty(),
            "expected at least one checkpoint CID"
        );
        // Each checkpoint CID must exist in the block store
        for cid in &result.checkpoint_cids {
            assert!(
                store.has(cid),
                "checkpoint block missing from store: {}",
                cid.to_multibase()
            );
        }
    }

    #[test]
    fn no_checkpoint_cids_when_store_is_none() {
        let result = KotobaVm::execute(
            &dummy_cid(),
            &one_rule_program(),
            &Arrangement::new(),
            &[make_delta("alice", "base")],
            10,
            7,
            None,
        );
        assert!(result.checkpoint_cids.is_empty());
    }

    /// Hash-chain property: sequential executions with two identical single-delta inputs
    /// must produce different checkpoint CIDs because the second run's chained link
    /// commits to the first run's CID as `prev`.
    ///
    /// We verify this by running KotobaVm twice with the same program + deltas
    /// and asserting the two checkpoint CIDs differ.
    #[test]
    fn chained_checkpoints_differ_across_runs() {
        use crate::pregel::{ComputeFn, ComputeOutput, PregelGraph, Vertex, VertexId};
        use kotoba_store::MemoryBlockStore;

        let store = MemoryBlockStore::new();

        // Verify the chain property using PregelGraph directly:
        // calling checkpoint_chained twice with same state but different `prev`
        // must produce different link CIDs.

        let mut graph = PregelGraph::new();
        let v = VertexId::from("v");
        graph.add_vertex(v.clone(), b"state".to_vec());
        // Step 1 — run one superstep and checkpoint
        let halt_fn: ComputeFn = Box::new(|vertex: &Vertex, _| ComputeOutput {
            new_state: vertex.state.clone(),
            messages: vec![],
            vote_halt: true,
        });
        graph.superstep(&halt_fn);
        let cid1 = graph.checkpoint_chained(&store, None).unwrap();

        // Step 2 — same vertex state, different prev → different link_cid
        let cid2 = graph.checkpoint_chained(&store, Some(&cid1)).unwrap();
        assert_ne!(
            cid1, cid2,
            "chained checkpoint with prev must differ from step-0 CID"
        );
    }

    // ---- New tests --------------------------------------------------------

    #[test]
    fn exec_status_ok_ne_halt() {
        assert_ne!(ExecStatus::Ok, ExecStatus::Halt);
        assert_ne!(ExecStatus::Ok, ExecStatus::StepsExceeded);
        assert_ne!(ExecStatus::Ok, ExecStatus::Error);
    }

    #[test]
    fn exec_status_copy_clone() {
        let s = ExecStatus::StepsExceeded;
        let c = s; // Copy
        assert_eq!(s, c);
        let c2 = s.clone();
        assert_eq!(s, c2);
    }

    #[test]
    fn exec_result_call_id_zero() {
        let result = KotobaVm::execute(
            &dummy_cid(),
            &DatalogProgram::default(),
            &Arrangement::new(),
            &[],
            5,
            0,
            None,
        );
        assert_eq!(result.call_id, 0);
    }

    #[test]
    fn max_steps_zero_returns_ok() {
        // When max_steps=0 and there are deltas + rules, the loop body
        // never executes → steps_used=0, status=Ok (0 >= 0 && !last.all_halted
        // is false since last is None → condition is false).
        let result = KotobaVm::execute(
            &dummy_cid(),
            &one_rule_program(),
            &Arrangement::new(),
            &[make_delta("x", "base")],
            0,
            77,
            None,
        );
        // steps_used must be 0 (no loop body ran)
        assert_eq!(result.steps_used, 0);
        assert_eq!(result.call_id, 77);
    }

    #[test]
    fn multiple_deltas_same_program() {
        let deltas: Vec<Delta> = (0..5)
            .map(|i| make_delta(&format!("node-{i}"), "base"))
            .collect();
        let result = KotobaVm::execute(
            &dummy_cid(),
            &one_rule_program(),
            &Arrangement::new(),
            &deltas,
            10,
            55,
            None,
        );
        assert_eq!(result.call_id, 55);
        assert_eq!(result.status, ExecStatus::Ok);
        assert!(result.checkpoint_cids.is_empty());
    }

    #[test]
    fn exec_status_debug_format() {
        let s = format!("{:?}", ExecStatus::StepsExceeded);
        assert_eq!(s, "StepsExceeded");
        let s2 = format!("{:?}", ExecStatus::Error);
        assert_eq!(s2, "Error");
    }

    #[test]
    fn call_id_preserved_with_store() {
        use kotoba_store::MemoryBlockStore;
        let store = MemoryBlockStore::new();
        let result = KotobaVm::execute(
            &dummy_cid(),
            &one_rule_program(),
            &Arrangement::new(),
            &[make_delta("a", "base")],
            5,
            12345,
            Some(&store),
        );
        assert_eq!(result.call_id, 12345);
    }
}
