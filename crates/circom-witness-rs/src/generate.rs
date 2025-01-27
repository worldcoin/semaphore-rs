#![allow(non_snake_case)]

use crate::field::{self, *};
use crate::graph::{self, Node};
use crate::HashSignalInfo;
use byteorder::{LittleEndian, ReadBytesExt};
use ffi::InputOutputList;
use ruint::{aliases::U256, uint};
use serde::{Deserialize, Serialize};
use std::{io::Read, time::Instant};

#[cxx::bridge]
mod ffi {

    #[derive(Debug, Default, Clone)]
    pub struct InputOutputList {
        pub defs: Vec<IODef>,
    }

    #[derive(Debug, Clone, Default)]
    pub struct IODef {
        pub code: usize,
        pub offset: usize,
        pub lengths: Vec<usize>,
    }

    #[derive(Debug, Default, Clone)]
    struct Circom_Component {
        templateId: u64,
        signalStart: u64,
        inputCounter: u64,
        templateName: String,
        componentName: String,
        idFather: u64,
        subcomponents: Vec<u32>,
        outputIsSet: Vec<bool>,
    }

    #[derive(Debug)]
    struct Circom_CalcWit {
        signalValues: Vec<FrElement>,
        componentMemory: Vec<Circom_Component>,
        circuitConstants: Vec<FrElement>,
        templateInsId2IOSignalInfoList: Vec<InputOutputList>,
        listOfTemplateMessages: Vec<String>,
    }

    // Rust types and signatures exposed to C++.
    extern "Rust" {
        type FrElement;

        fn create_vec(len: usize) -> Vec<FrElement>;
        fn create_vec_u32(len: usize) -> Vec<u32>;
        fn generate_position_array(
            prefix: String,
            dimensions: Vec<u32>,
            size_dimensions: u32,
            index: u32,
        ) -> String;

        // Field operations
        unsafe fn Fr_mul(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_add(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_sub(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_copy(to: *mut FrElement, a: *const FrElement);
        unsafe fn Fr_copyn(to: *mut FrElement, a: *const FrElement, n: usize);
        // unsafe fn Fr_neg(to: *mut FrElement, a: *const FrElement);
        // unsafe fn Fr_inv(to: *mut FrElement, a: *const FrElement);
        // unsafe fn Fr_div(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        // unsafe fn Fr_square(to: *mut FrElement, a: *const FrElement);
        unsafe fn Fr_shl(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_shr(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_band(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        // fn Fr_bor(to: &mut FrElement, a: &FrElement, b: &FrElement);
        // fn Fr_bxor(to: &mut FrElement, a: &FrElement, b: &FrElement);
        // fn Fr_bnot(to: &mut FrElement, a: &FrElement);
        unsafe fn Fr_eq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_neq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_lt(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_gt(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_leq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_geq(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn Fr_isTrue(a: *mut FrElement) -> bool;
        // fn Fr_fromBool(to: &mut FrElement, a: bool);
        unsafe fn Fr_toInt(a: *mut FrElement) -> u64;
        unsafe fn Fr_lor(to: *mut FrElement, a: *const FrElement, b: *const FrElement);
        unsafe fn print(a: *mut FrElement);
        // fn Fr_pow(to: &mut FrElement, a: &FrElement, b: &FrElement);
        // fn Fr_idiv(to: &mut FrElement, a: &FrElement, b: &FrElement);
    }

    // C++ types and signatures exposed to Rust.
    unsafe extern "C++" {
        include!("witness/include/witness.h");

        unsafe fn run(ctx: *mut Circom_CalcWit);
        fn get_size_of_io_map() -> u32;
        fn get_total_signal_no() -> u32;
        fn get_main_input_signal_no() -> u32;
        fn get_main_input_signal_start() -> u32;
        fn get_number_of_components() -> u32;
        fn get_size_of_constants() -> u32;
        fn get_size_of_input_hashmap() -> u32;
        fn get_size_of_witness() -> u32;
    }
}

const DAT_BYTES: &[u8] = include_bytes!("constants.dat");

pub fn get_input_hash_map() -> Vec<HashSignalInfo> {
    let mut bytes = &DAT_BYTES[..(ffi::get_size_of_input_hashmap() as usize) * 24];
    let mut input_hash_map =
        vec![HashSignalInfo::default(); ffi::get_size_of_input_hashmap() as usize];
    for i in 0..ffi::get_size_of_input_hashmap() as usize {
        let hash = bytes.read_u64::<LittleEndian>().unwrap();
        let signalid = bytes.read_u64::<LittleEndian>().unwrap();
        let signalsize = bytes.read_u64::<LittleEndian>().unwrap();
        input_hash_map[i] = HashSignalInfo {
            hash,
            signalid,
            signalsize,
        };
    }
    input_hash_map
}

pub fn get_witness_to_signal() -> Vec<usize> {
    let mut bytes = &DAT_BYTES[(ffi::get_size_of_input_hashmap() as usize) * 24
        ..(ffi::get_size_of_input_hashmap() as usize) * 24
            + (ffi::get_size_of_witness() as usize) * 8];
    let mut signal_list = Vec::with_capacity(ffi::get_size_of_witness() as usize);
    for i in 0..ffi::get_size_of_witness() as usize {
        signal_list.push(bytes.read_u64::<LittleEndian>().unwrap() as usize);
    }
    signal_list
}

pub fn get_constants() -> Vec<FrElement> {
    if ffi::get_size_of_constants() == 0 {
        return vec![];
    }

    // skip the first part
    let mut bytes = &DAT_BYTES[(ffi::get_size_of_input_hashmap() as usize) * 24
        + (ffi::get_size_of_witness() as usize) * 8..];
    let mut constants = vec![field::constant(U256::from(0)); ffi::get_size_of_constants() as usize];
    for i in 0..ffi::get_size_of_constants() as usize {
        let sv = bytes.read_i32::<LittleEndian>().unwrap() as i32;
        let typ = bytes.read_u32::<LittleEndian>().unwrap() as u32;

        let mut buf = [0; 32];
        bytes.read_exact(&mut buf);

        if typ & 0x80000000 == 0 {
            constants[i] = field::constant(U256::from(sv));
        } else {
            constants[i] =
                field::constant(U256::from_le_bytes(buf).mul_redc(uint!(1_U256), M, INV));
        }
    }

    return constants;
}

pub fn get_iosignals() -> Vec<InputOutputList> {
    if ffi::get_size_of_io_map() == 0 {
        return vec![];
    }

    // skip the first part
    let mut bytes = &DAT_BYTES[(ffi::get_size_of_input_hashmap() as usize) * 24
        + (ffi::get_size_of_witness() as usize) * 8
        + (ffi::get_size_of_constants() as usize * 40)..];
    let io_size = ffi::get_size_of_io_map() as usize;
    let hashmap_size = ffi::get_size_of_input_hashmap() as usize;
    let mut indices = vec![0usize; io_size];
    let mut map: Vec<InputOutputList> = vec![InputOutputList::default(); hashmap_size];

    (0..io_size).for_each(|i| {
        let t32 = bytes.read_u32::<LittleEndian>().unwrap() as usize;
        indices[i] = t32;
    });

    (0..io_size).for_each(|i| {
        let l32 = bytes.read_u32::<LittleEndian>().unwrap() as usize;
        let mut io_list: InputOutputList = InputOutputList { defs: vec![] };

        (0..l32).for_each(|_j| {
            let offset = bytes.read_u32::<LittleEndian>().unwrap() as usize;
            let len = bytes.read_u32::<LittleEndian>().unwrap() as usize + 1;

            let mut lengths = vec![0usize; len];

            (1..len).for_each(|k| {
                lengths[k] = bytes.read_u32::<LittleEndian>().unwrap() as usize;
            });

            io_list.defs.push(ffi::IODef {
                code: 0,
                offset,
                lengths,
            });
        });
        map[indices[i] % hashmap_size] = io_list;
    });
    map
}

/// Run cpp witness generator and optimize graph
pub fn build_witness() -> color_color_eyre::Result<()> {
    let mut signal_values = vec![field::undefined(); ffi::get_total_signal_no() as usize];
    signal_values[0] = field::constant(uint!(1_U256));

    let total_input_len =
        (ffi::get_main_input_signal_no() + ffi::get_main_input_signal_start()) as usize;

    for i in 0..total_input_len {
        signal_values[i + 1] = field::input(i + 1, uint!(0_U256));
    }

    let mut ctx = ffi::Circom_CalcWit {
        signalValues: signal_values,
        componentMemory: vec![
            ffi::Circom_Component::default();
            ffi::get_number_of_components() as usize
        ],
        circuitConstants: get_constants(),
        templateInsId2IOSignalInfoList: get_iosignals(),
        listOfTemplateMessages: vec![],
    };

    // measure time
    let now = Instant::now();
    unsafe {
        ffi::run(&mut ctx as *mut _);
    }
    eprintln!("Calculation took: {:?}", now.elapsed());

    let signal_values = get_witness_to_signal();
    let mut signals = signal_values
        .into_iter()
        .map(|i| ctx.signalValues[i].0)
        .collect::<Vec<_>>();
    let mut nodes = field::get_graph();
    eprintln!("Graph with {} nodes", nodes.len());

    // Optimize graph
    graph::optimize(&mut nodes, &mut signals);

    // Store graph to file.
    let input_map = get_input_hash_map();
    let bytes = postcard::to_stdvec(&(&nodes, &signals, &input_map)).unwrap();
    eprintln!("Graph size: {} bytes", bytes.len());
    std::fs::write("graph.bin", bytes).unwrap();

    // Evaluate the graph.
    let input_len = (ffi::get_main_input_signal_no() + ffi::get_main_input_signal_start()) as usize; // TODO: fetch from file
    let mut inputs = vec![U256::from(0); input_len];
    inputs[0] = U256::from(1);
    for i in 1..nodes.len() {
        if let Node::Input(j) = nodes[i] {
            inputs[j] = get_values()[i];
        } else {
            break;
        }
    }

    let now = Instant::now();
    for _ in 0..10 {
        _ = graph::evaluate(&nodes, &inputs, &signals);
    }
    eprintln!("Calculation took: {:?}", now.elapsed() / 10);

    // Print graph
    // for (i, node) in nodes.iter().enumerate() {
    //     println!("node[{}] = {:?}", i, node);
    // }
    // for (i, j) in signals.iter().enumerate() {
    //     println!("signal[{}] = node[{}]", i, j);
    // }

    Ok(())
}
