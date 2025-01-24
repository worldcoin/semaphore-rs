mod field;
pub mod graph;

#[cfg(feature = "build-witness")]
pub mod generate;

use std::collections::HashMap;

use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::graph::Node;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct HashSignalInfo {
    pub hash: u64,
    pub signalid: u64,
    pub signalsize: u64,
}

pub struct Graph {
    pub nodes: Vec<Node>,
    pub signals: Vec<usize>,
    pub input_mapping: Vec<HashSignalInfo>,
}

fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xCBF29CE484222325;
    for c in s.bytes() {
        hash ^= c as u64;
        hash = hash.wrapping_mul(0x100000001B3);
    }
    hash
}

/// Loads the graph from bytes
pub fn init_graph(graph_bytes: &[u8]) -> color_eyre::Result<Graph> {
    let (nodes, signals, input_mapping): (Vec<Node>, Vec<usize>, Vec<HashSignalInfo>) =
        postcard::from_bytes(graph_bytes)?;

    Ok(Graph {
        nodes,
        signals,
        input_mapping,
    })
}

/// Calculates the number of needed inputs
pub fn get_inputs_size(graph: &Graph) -> usize {
    let mut start = false;
    let mut max_index = 0usize;
    for &node in graph.nodes.iter() {
        if let Node::Input(i) = node {
            if i > max_index {
                max_index = i;
            }
            start = true
        } else if start {
            break;
        }
    }
    max_index + 1
}

/// Allocates inputs vec with position 0 set to 1
pub fn get_inputs_buffer(size: usize) -> Vec<U256> {
    let mut inputs = vec![U256::ZERO; size];
    inputs[0] = U256::from(1);
    inputs
}

/// Calculates the position of the given signal in the inputs buffer
pub fn get_input_mapping(input_list: &Vec<String>, graph: &Graph) -> HashMap<String, usize> {
    let mut input_mapping = HashMap::new();
    for key in input_list {
        let h = fnv1a(key);
        let pos = graph
            .input_mapping
            .iter()
            .position(|x| x.hash == h)
            .unwrap();
        let si = (graph.input_mapping[pos].signalid) as usize;
        input_mapping.insert(key.to_string(), si);
    }
    input_mapping
}

/// Sets all provided inputs given the mapping and inputs buffer
pub fn populate_inputs(
    input_list: &HashMap<String, Vec<U256>>,
    input_mapping: &HashMap<String, usize>,
    input_buffer: &mut [U256],
) {
    for (key, value) in input_list {
        let start = input_mapping[key];
        let end = start + value.len();
        input_buffer[start..end].copy_from_slice(value);
    }
}

/// Calculate witness based on serialized graph and inputs
pub fn calculate_witness(
    input_list: HashMap<String, Vec<U256>>,
    graph: &Graph,
) -> color_eyre::Result<Vec<U256>> {
    let mut inputs_buffer = get_inputs_buffer(get_inputs_size(graph));
    let input_mapping = get_input_mapping(&input_list.keys().cloned().collect(), graph);
    populate_inputs(&input_list, &input_mapping, &mut inputs_buffer);
    Ok(graph::evaluate(
        &graph.nodes,
        &inputs_buffer,
        &graph.signals,
    ))
}
