//! ReAct (Reason + Act) agent loop for KOTOBA.
//!
//! Two execution backends:
//!
//! 1. `ReActRunner`       — simple sync loop (test / embedded use).
//! 2. `PregelReActRunner` — BSP superstep engine via `PregelGraph`.
//!
//! **Pregel mapping**
//!   vertex_id  = session CID
//!   vertex.state = CBOR of `AgentSnapshot` (steps + quad log)
//!   superstep  = one ReAct cycle (Thought → Action → Observation)
//!   self-message → continue next superstep
//!   vote_halt  → finish action fired OR step limit reached
//!
//! Tools available to the agent:
//!   kqe.assert(<json>)     — append Quad to session quad log
//!   kqe.query(<datalog>)   — list quads from session log
//!   kse.publish(<t>,<msg>) — record a publish event
//!   finish(<answer>)       — terminal; halts the vertex

use std::fmt::Write as FmtWrite;
use kotoba_core::cid::KotobaCid;
use kotoba_kqe::{
    arrangement::Arrangement,
    quad::{Quad, QuadObject},
    delta::Delta,
};
use kotoba_runtime::host::InferenceFn;

// ---------------------------------------------------------------------------
// ReAct step types (shared between both backends)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReActStep {
    Thought     { text: String },
    Action      { tool: String, input: String },
    Observation { output: String },
    Finish      { answer: String },
}

// ---------------------------------------------------------------------------
// AgentSession — carries all mutable state for one agent run
// ---------------------------------------------------------------------------

pub struct AgentSession {
    pub session_cid:  KotobaCid,
    pub graph_cid:    KotobaCid,
    pub task:         String,
    pub steps:        Vec<ReActStep>,
    pub arrangement:  Arrangement,
    pub max_steps:    u32,
}

impl AgentSession {
    pub fn new(task: impl Into<String>, graph_cid: KotobaCid, max_steps: u32) -> Self {
        let task = task.into();
        let session_cid = KotobaCid::from_bytes(
            format!("agent/{}/{}", graph_cid.to_multibase(), &task[..task.len().min(64)]).as_bytes(),
        );
        Self {
            session_cid,
            graph_cid,
            task,
            steps:       Vec::new(),
            arrangement: Arrangement::new(),
            max_steps,
        }
    }
}

// ---------------------------------------------------------------------------
// AgentSnapshot — serializable vertex state for Pregel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AgentSnapshot {
    pub task:      String,
    pub steps:     Vec<ReActStep>,
    pub quads:     Vec<(String, String, String)>, // (subject_mb, predicate, object_json)
    pub max_steps: u32,
}

impl AgentSnapshot {
    fn from_session(s: &AgentSession) -> Self {
        Self {
            task:      s.task.clone(),
            steps:     s.steps.clone(),
            quads:     vec![],
            max_steps: s.max_steps,
        }
    }

    fn assert_quad(&mut self, graph_cid: &KotobaCid, input: &str) -> String {
        // Try JSON Quad first, fall back to text
        let (subj, pred, obj) = if let Ok(q) = serde_json::from_str::<Quad>(input) {
            (q.subject.to_multibase(), q.predicate.clone(),
             serde_json::to_string(&q.object).unwrap_or_else(|_| input.to_string()))
        } else {
            let obj_val = QuadObject::Text(input.to_string());
            (KotobaCid::from_bytes(input.as_bytes()).to_multibase(),
             "agent/fact".to_string(),
             serde_json::to_string(&obj_val).unwrap_or_default())
        };
        self.quads.push((subj, pred, obj));
        format!("asserted; quad log now has {} entries", self.quads.len())
    }

    fn query_quads(&self, graph_cid: &KotobaCid) -> String {
        if self.quads.is_empty() {
            return "quad log is empty".to_string();
        }
        let preview: Vec<String> = self.quads.iter().take(5)
            .map(|(s, p, o)| format!("({s} {p} {o})"))
            .collect();
        format!("{} quads: [{}{}]",
            self.quads.len(),
            preview.join(", "),
            if self.quads.len() > 5 { ", ..." } else { "" })
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

fn build_prompt(task: &str, steps: &[ReActStep]) -> String {
    let mut p = String::new();
    let _ = writeln!(p, "You are a KOTOBA agent. Use ReAct to answer the task.");
    let _ = writeln!(p, "Tools: kqe.assert(<quad>), kqe.query(<q>), kse.publish(<t>,<m>), finish(<answer>)");
    let _ = writeln!(p, "\nTask: {task}\n");
    for step in steps {
        match step {
            ReActStep::Thought     { text }        => { let _ = writeln!(p, "Thought: {text}"); }
            ReActStep::Action      { tool, input } => { let _ = writeln!(p, "Action: {tool}({input})"); }
            ReActStep::Observation { output }      => { let _ = writeln!(p, "Observation: {output}"); }
            ReActStep::Finish      { answer }      => { let _ = writeln!(p, "Answer: {answer}"); }
        }
    }
    let _ = write!(p, "Thought:");
    p
}

fn parse_action(text: &str) -> (String, String) {
    let line = text.lines().next().unwrap_or(text).trim();
    let line = line.strip_prefix("Action:").unwrap_or(line).trim();
    if let Some(paren) = line.find('(') {
        let tool  = line[..paren].trim().to_string();
        let rest  = &line[paren + 1..];
        let input = rest.strip_suffix(')').unwrap_or(rest).trim().to_string();
        if !tool.is_empty() {
            return (tool, input);
        }
    }
    ("finish".to_string(), line.to_string())
}

// ---------------------------------------------------------------------------
// Backend 1: simple sync ReActRunner (unchanged API)
// ---------------------------------------------------------------------------

pub struct ReActRunner {
    inference_engine: InferenceFn,
    max_tokens:       usize,
}

impl ReActRunner {
    pub fn new(inference_engine: InferenceFn, max_tokens: usize) -> Self {
        Self { inference_engine, max_tokens }
    }

    pub fn run(&self, mut session: AgentSession) -> AgentSession {
        for _ in 0..session.max_steps {
            let prompt = build_prompt(&session.task, &session.steps);
            let thought_text = match (self.inference_engine)(&prompt, self.max_tokens) {
                Ok(t)  => t.trim().to_string(),
                Err(e) => {
                    session.steps.push(ReActStep::Observation {
                        output: format!("inference error: {e}"),
                    });
                    continue;
                }
            };
            session.steps.push(ReActStep::Thought { text: thought_text.clone() });
            let (tool, input) = parse_action(&thought_text);
            session.steps.push(ReActStep::Action { tool: tool.clone(), input: input.clone() });

            match tool.as_str() {
                "finish" => {
                    session.steps.push(ReActStep::Finish { answer: input });
                    return session;
                }
                "kqe.assert" => {
                    let obs = exec_assert(&mut session.arrangement, &session.graph_cid, &input);
                    session.steps.push(ReActStep::Observation { output: obs });
                }
                "kqe.query" => {
                    let obs = exec_query(&session.arrangement, &session.graph_cid);
                    session.steps.push(ReActStep::Observation { output: obs });
                }
                "kse.publish" => {
                    session.steps.push(ReActStep::Observation {
                        output: format!("published: {}", &input[..input.len().min(64)]),
                    });
                }
                unknown => {
                    session.steps.push(ReActStep::Observation {
                        output: format!("unknown tool: {unknown}"),
                    });
                }
            }
        }
        session.steps.push(ReActStep::Finish {
            answer: format!("max_steps={} reached", session.max_steps),
        });
        session
    }
}

fn exec_assert(arr: &mut Arrangement, graph_cid: &KotobaCid, input: &str) -> String {
    let quad: Quad = match serde_json::from_str(input) {
        Ok(q) => q,
        Err(_) => Quad {
            graph:     graph_cid.clone(),
            subject:   KotobaCid::from_bytes(input.as_bytes()),
            predicate: "agent/fact".to_string(),
            object:    QuadObject::Text(input.to_string()),
        },
    };
    arr.insert(&quad);
    format!("asserted; arrangement has {} quads", arr.len())
}

fn exec_query(arr: &Arrangement, graph_cid: &KotobaCid) -> String {
    let quads = arr.quads(graph_cid);
    if quads.is_empty() {
        "no quads in arrangement".to_string()
    } else {
        let preview: Vec<String> = quads.iter().take(5)
            .map(|q| format!("({} {} {:?})", q.subject.to_multibase(), q.predicate, q.object))
            .collect();
        format!("{} quads: [{}{}]",
            quads.len(), preview.join(", "),
            if quads.len() > 5 { ", ..." } else { "" })
    }
}

// ---------------------------------------------------------------------------
// Backend 2: PregelReActRunner — one superstep = one ReAct cycle
// ---------------------------------------------------------------------------

/// Runs the ReAct loop inside a `PregelGraph`.
///
/// Mapping:
///   vertex_id  = session CID
///   vertex.state = JSON of `AgentSnapshot`
///   superstep  = one cycle: Thought + Action + Observation
///   self-message  → advance to next superstep
///   vote_halt  → finish action fired OR step limit reached
pub struct PregelReActRunner {
    inference_engine: InferenceFn,
    max_tokens:       usize,
}

impl PregelReActRunner {
    pub fn new(inference_engine: InferenceFn, max_tokens: usize) -> Self {
        Self { inference_engine, max_tokens }
    }

    /// Run the agent using the Pregel BSP engine.
    /// Returns the completed `AgentSession`.
    pub fn run(&self, session: AgentSession) -> (AgentSession, Vec<crate::pregel::SuperstepResult>) {
        use crate::pregel::{PregelGraph, VertexId, Message, ComputeOutput, ComputeFn};

        let vid = VertexId(session.session_cid.clone());
        let graph_cid = session.graph_cid.clone();
        let max_steps = session.max_steps;

        let initial_snap = AgentSnapshot::from_session(&session);
        let initial_state = serde_json::to_vec(&initial_snap).unwrap_or_default();

        let mut graph = PregelGraph::new();
        graph.add_vertex(vid.clone(), initial_state);
        // Seed message activates the vertex for superstep 0
        graph.inject_message(Message {
            src:     vid.clone(),
            dst:     vid.clone(),
            payload: b"start".to_vec(),
        });

        let engine     = self.inference_engine.clone();
        let max_tokens = self.max_tokens;

        let compute: ComputeFn = Box::new(move |vertex, inbox| {
            // No inbox → already halted; nothing to do
            if inbox.is_empty() {
                return ComputeOutput {
                    new_state:  vertex.state.clone(),
                    messages:   vec![],
                    vote_halt:  true,
                };
            }

            // Decode snapshot
            let mut snap: AgentSnapshot =
                serde_json::from_slice(&vertex.state).unwrap_or_default();

            // Step limit guard
            let cycles_done = snap.steps.iter()
                .filter(|s| matches!(s, ReActStep::Thought { .. }))
                .count() as u32;
            if cycles_done >= max_steps {
                snap.steps.push(ReActStep::Finish {
                    answer: format!("pregel max_steps={max_steps} reached"),
                });
                return ComputeOutput {
                    new_state: serde_json::to_vec(&snap).unwrap_or_default(),
                    messages:  vec![],
                    vote_halt: true,
                };
            }

            // ── Thought ────────────────────────────────────────────────────
            let prompt = build_prompt(&snap.task, &snap.steps);
            let thought_text = match engine(&prompt, max_tokens) {
                Ok(t)  => t.trim().to_string(),
                Err(e) => {
                    snap.steps.push(ReActStep::Observation {
                        output: format!("inference error: {e}"),
                    });
                    let msg = Message { src: vertex.id.clone(), dst: vertex.id.clone(), payload: b"cont".to_vec() };
                    return ComputeOutput {
                        new_state: serde_json::to_vec(&snap).unwrap_or_default(),
                        messages:  vec![msg],
                        vote_halt: false,
                    };
                }
            };
            snap.steps.push(ReActStep::Thought { text: thought_text.clone() });

            // ── Action ─────────────────────────────────────────────────────
            let (tool, input) = parse_action(&thought_text);
            snap.steps.push(ReActStep::Action { tool: tool.clone(), input: input.clone() });

            // ── Observation / halt decision ────────────────────────────────
            let done = match tool.as_str() {
                "finish" => {
                    snap.steps.push(ReActStep::Finish { answer: input.clone() });
                    true
                }
                "kqe.assert" => {
                    let obs = snap.assert_quad(&graph_cid, &input);
                    snap.steps.push(ReActStep::Observation { output: obs });
                    false
                }
                "kqe.query" => {
                    let obs = snap.query_quads(&graph_cid);
                    snap.steps.push(ReActStep::Observation { output: obs });
                    false
                }
                "kse.publish" => {
                    snap.steps.push(ReActStep::Observation {
                        output: format!("published: {}", &input[..input.len().min(64)]),
                    });
                    false
                }
                unknown => {
                    snap.steps.push(ReActStep::Observation {
                        output: format!("unknown tool: {unknown}"),
                    });
                    false
                }
            };

            let new_state = serde_json::to_vec(&snap).unwrap_or_default();

            // Continue loop via self-message; halt when done
            let messages = if done { vec![] } else {
                vec![Message { src: vertex.id.clone(), dst: vertex.id.clone(), payload: b"cont".to_vec() }]
            };
            ComputeOutput { new_state, messages, vote_halt: done }
        });

        let superstep_results = graph.run(&compute, max_steps + 1);

        // Decode final vertex state back into AgentSession
        let final_state = graph.vertex(&vid)
            .map(|v| v.state.clone())
            .unwrap_or_default();
        let final_snap: AgentSnapshot =
            serde_json::from_slice(&final_state).unwrap_or_default();

        let mut arr = Arrangement::new();
        for (subj_mb, pred, obj_json) in &final_snap.quads {
            if let (Some(subject), Ok(obj)) = (
                KotobaCid::from_multibase(subj_mb),
                serde_json::from_str::<QuadObject>(obj_json),
            ) {
                arr.insert(&Quad {
                    graph:     session.graph_cid.clone(),
                    subject,
                    predicate: pred.clone(),
                    object:    obj,
                });
            }
        }

        let out_session = AgentSession {
            session_cid:  session.session_cid,
            graph_cid:    session.graph_cid,
            task:         session.task,
            steps:        final_snap.steps,
            arrangement:  arr,
            max_steps:    session.max_steps,
        };
        (out_session, superstep_results)
    }
}

// ---------------------------------------------------------------------------
// Quads produced by a session — store history in QuadStore
// ---------------------------------------------------------------------------

pub fn session_to_quads(session: &AgentSession) -> Vec<Delta> {
    session.steps.iter().enumerate().map(|(i, step)| {
        let text = match step {
            ReActStep::Thought     { text }        => format!("thought:{text}"),
            ReActStep::Action      { tool, input } => format!("action:{tool}({input})"),
            ReActStep::Observation { output }      => format!("observation:{output}"),
            ReActStep::Finish      { answer }      => format!("finish:{answer}"),
        };
        Delta::assert(Quad {
            graph:     session.graph_cid.clone(),
            subject:   session.session_cid.clone(),
            predicate: format!("agent/step/{i}"),
            object:    QuadObject::Text(text),
        })
    }).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_engine(response: &'static str) -> InferenceFn {
        Arc::new(move |_: &str, _: usize| Ok(response.to_string()))
    }

    fn counter_engine(responses: Vec<&'static str>) -> InferenceFn {
        let responses = Arc::new(responses);
        let i = Arc::new(std::sync::Mutex::new(0usize));
        Arc::new(move |_: &str, _: usize| {
            let mut idx = i.lock().unwrap();
            let r = responses.get(*idx).copied().unwrap_or("finish(done)");
            *idx += 1;
            Ok(r.to_string())
        })
    }

    fn graph() -> KotobaCid { KotobaCid::from_bytes(b"test-graph") }

    // ── ReActRunner (simple backend) ──────────────────────────────────────

    #[test]
    fn simple_finish_on_first_step() {
        let runner  = ReActRunner::new(make_engine("finish(the answer is 42)"), 128);
        let session = AgentSession::new("test task", graph(), 10);
        let result  = runner.run(session);
        assert!(matches!(result.steps.last(), Some(ReActStep::Finish { .. })));
    }

    #[test]
    fn simple_assert_then_finish() {
        let engine = counter_engine(vec!["kqe.assert(some fact)", "finish(done)"]);
        let runner  = ReActRunner::new(engine, 128);
        let session = AgentSession::new("test", graph(), 10);
        let result  = runner.run(session);
        let n_obs = result.steps.iter().filter(|s| matches!(s, ReActStep::Observation { .. })).count();
        assert_eq!(n_obs, 1);
        assert!(matches!(result.steps.last(), Some(ReActStep::Finish { .. })));
    }

    #[test]
    fn simple_max_steps_terminates() {
        let runner  = ReActRunner::new(make_engine("kqe.query(*)"), 64);
        let session = AgentSession::new("loop", graph(), 3);
        let result  = runner.run(session);
        assert!(matches!(result.steps.last(), Some(ReActStep::Finish { .. })));
    }

    // ── PregelReActRunner (Pregel backend) ────────────────────────────────

    #[test]
    fn pregel_finish_on_first_superstep() {
        let runner  = PregelReActRunner::new(make_engine("finish(pregel answer)"), 128);
        let session = AgentSession::new("pregel test", graph(), 5);
        let (result, supersteps) = runner.run(session);

        assert!(matches!(result.steps.last(), Some(ReActStep::Finish { .. })));
        if let Some(ReActStep::Finish { answer }) = result.steps.last() {
            assert!(answer.contains("pregel answer"), "got: {answer}");
        }
        // Should halt after 1 superstep (finish action → vote_halt=true)
        assert_eq!(supersteps.len(), 1, "expected 1 superstep, got {}", supersteps.len());
        assert!(supersteps[0].all_halted);
    }

    #[test]
    fn pregel_assert_then_finish() {
        let engine = counter_engine(vec!["kqe.assert(alice knows bob)", "finish(stored)"]);
        let runner  = PregelReActRunner::new(engine, 128);
        let session = AgentSession::new("store a fact", graph(), 5);
        let (result, supersteps) = runner.run(session);

        let n_obs = result.steps.iter().filter(|s| matches!(s, ReActStep::Observation { .. })).count();
        assert_eq!(n_obs, 1);
        assert!(matches!(result.steps.last(), Some(ReActStep::Finish { .. })));
        assert_eq!(supersteps.len(), 2, "superstep 1=assert, superstep 2=finish");

        // The fact should be in the arrangement (reconstructed from snapshot quads)
        assert_eq!(result.arrangement.len(), 1);
    }

    #[test]
    fn pregel_query_after_assert() {
        let engine = counter_engine(vec![
            "kqe.assert(alice knows bob)",
            "kqe.query(*)",
            "finish(queried)",
        ]);
        let runner  = PregelReActRunner::new(engine, 128);
        let session = AgentSession::new("assert then query", graph(), 5);
        let (result, supersteps) = runner.run(session);

        assert!(matches!(result.steps.last(), Some(ReActStep::Finish { .. })));
        // 3 supersteps: assert, query, finish
        assert_eq!(supersteps.len(), 3);
    }

    #[test]
    fn pregel_max_steps_terminates() {
        let runner  = PregelReActRunner::new(make_engine("kqe.query(*)"), 64);
        let session = AgentSession::new("infinite loop", graph(), 3);
        let (result, _) = runner.run(session);
        assert!(matches!(result.steps.last(), Some(ReActStep::Finish { .. })));
    }

    #[test]
    fn pregel_superstep_count_matches_cycles() {
        // 2 cycles (assert + query) then finish → 3 supersteps
        let engine = counter_engine(vec![
            "kqe.assert(fact-a)",
            "kqe.assert(fact-b)",
            "finish(both stored)",
        ]);
        let runner  = PregelReActRunner::new(engine, 64);
        let session = AgentSession::new("two asserts", graph(), 5);
        let (result, supersteps) = runner.run(session);

        assert!(matches!(result.steps.last(), Some(ReActStep::Finish { .. })));
        assert_eq!(supersteps.len(), 3);
        assert_eq!(result.arrangement.len(), 2, "both quads should be in arrangement");
    }

    #[test]
    fn pregel_checkpoint_persists_state() {
        use kotoba_store::MemoryBlockStore;
        use kotoba_core::store::BlockStore as _;

        // Run the agent
        let engine = counter_engine(vec!["kqe.assert(data)", "finish(done)"]);
        let runner  = PregelReActRunner::new(engine, 64);
        let session = AgentSession::new("checkpoint test", graph(), 5);
        let (_, _) = runner.run(session);

        // Checkpoint an independent Pregel graph to a MemoryBlockStore
        use crate::pregel::{PregelGraph, VertexId};
        let mut g = PregelGraph::new();
        g.add_vertex(VertexId::from_str("agent"), b"state".to_vec());
        let store = MemoryBlockStore::new();
        let cid = g.checkpoint(&store).unwrap();
        assert!(store.has(&cid));
    }

    // ── parse_action ──────────────────────────────────────────────────────

    #[test]
    fn parse_with_action_prefix() {
        let (tool, input) = parse_action("Action: finish(hello world)");
        assert_eq!(tool, "finish");
        assert_eq!(input, "hello world");
    }

    #[test]
    fn parse_direct() {
        let (tool, input) = parse_action("kqe.query(some datalog)");
        assert_eq!(tool, "kqe.query");
        assert_eq!(input, "some datalog");
    }

    // ── session_to_quads ──────────────────────────────────────────────────

    #[test]
    fn session_quads_count_matches_steps() {
        let engine  = make_engine("finish(ok)");
        let runner  = PregelReActRunner::new(engine, 64);
        let session = AgentSession::new("t", graph(), 5);
        let (result, _) = runner.run(session);
        let deltas = session_to_quads(&result);
        assert_eq!(deltas.len(), result.steps.len());
        assert!(deltas.iter().all(|d| d.is_assert()));
    }
}
