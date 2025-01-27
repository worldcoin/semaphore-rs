#![allow(unused, non_snake_case)]

use crate::graph::{Node, Operation};
use ruint::{aliases::U256, uint};
use std::{ptr, sync::Mutex};

pub const M: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

pub const INV: u64 = 14042775128853446655;

pub const R: U256 = uint!(0x0e0a77c19a07df2f666ea36f7879462e36fc76959f60cd29ac96341c4ffffffb_U256);

static NODES: Mutex<Vec<Node>> = Mutex::new(Vec::new());
static VALUES: Mutex<Vec<U256>> = Mutex::new(Vec::new());
static CONSTANT: Mutex<Vec<bool>> = Mutex::new(Vec::new());

#[derive(Debug, Default, Clone, Copy)]
pub struct FrElement(pub usize);

pub fn print_eval() {
    let nodes = NODES.lock().unwrap();
    let values = VALUES.lock().unwrap();
    let constant = CONSTANT.lock().unwrap();

    let mut constants = 0_usize;
    for (i, node) in nodes.iter().enumerate() {
        print!("{}: {:?}", i, node);
        if constant[i] {
            constants += 1;
            println!(" = {}", values[i]);
        } else {
            println!();
        }
    }
    eprintln!(
        "{} nodes of which {} constant and {} dynamic",
        nodes.len(),
        constants,
        nodes.len() - constants
    );
}

pub fn get_graph() -> Vec<Node> {
    NODES.lock().unwrap().clone()
}

pub fn get_values() -> Vec<U256> {
    VALUES.lock().unwrap().clone()
}

pub fn undefined() -> FrElement {
    FrElement(usize::MAX)
}

pub fn constant(c: U256) -> FrElement {
    let mut nodes = NODES.lock().unwrap();
    let mut values = VALUES.lock().unwrap();
    let mut constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    nodes.push(Node::Constant(c));
    values.push(c);
    constant.push(true);

    FrElement(nodes.len() - 1)
}

pub fn input(i: usize, value: U256) -> FrElement {
    let mut nodes = NODES.lock().unwrap();
    let mut values = VALUES.lock().unwrap();
    let mut constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    nodes.push(Node::Input(i));
    values.push(value);
    constant.push(false);

    FrElement(nodes.len() - 1)
}

fn binop(op: Operation, to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    let mut nodes = NODES.lock().unwrap();
    let mut values = VALUES.lock().unwrap();
    let mut constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    let (a, b, to) = unsafe { ((*a).0, (*b).0, &mut (*to).0) };
    assert!(a < nodes.len());
    assert!(b < nodes.len());
    nodes.push(Node::Op(op, a, b));
    *to = nodes.len() - 1;

    let (va, vb) = (values[a], values[b]);
    values.push(op.eval(va, vb));

    let (ca, cb) = (constant[a], constant[b]);
    constant.push(ca && cb);
}

pub fn Fr_mul(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Mul, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_add(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Add, to, a, b);
}

#[allow(warnings)]
pub unsafe fn Fr_sub(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Sub, to, a, b);
}

#[allow(warnings)]
pub fn Fr_copy(to: *mut FrElement, a: *const FrElement) {
    unsafe {
        *to = *a;
    }
}

#[allow(warnings)]
pub fn Fr_copyn(to: *mut FrElement, a: *const FrElement, n: usize) {
    unsafe {
        ptr::copy_nonoverlapping(a, to, n);
    }
}

/// Create a vector of FrElement with length `len`.
/// Needed because the default constructor of opaque type is not implemented.
pub fn create_vec(len: usize) -> Vec<FrElement> {
    vec![FrElement(usize::MAX); len]
}

pub fn create_vec_u32(len: usize) -> Vec<u32> {
    vec![0; len]
}

pub fn generate_position_array(
    prefix: String,
    dimensions: Vec<u32>,
    size_dimensions: u32,
    index: u32,
) -> String {
    let mut positions: String = prefix;
    let mut index = index;
    for i in 0..size_dimensions {
        let last_pos = index % dimensions[size_dimensions as usize - 1 - i as usize];
        index /= dimensions[size_dimensions as usize - 1 - i as usize];
        let new_pos = format!("[{}]", last_pos);
        positions = new_pos + &positions;
    }
    positions
}

pub unsafe fn Fr_toInt(a: *const FrElement) -> u64 {
    let nodes = NODES.lock().unwrap();
    let values = VALUES.lock().unwrap();
    let constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    let a = unsafe { (*a).0 };
    assert!(a < nodes.len());
    assert!(constant[a]);
    values[a].try_into().unwrap()
}

pub unsafe fn print(a: *const FrElement) {
    println!("DEBUG>> {:?}", (*a).0);
}

pub fn Fr_isTrue(a: *mut FrElement) -> bool {
    let nodes = NODES.lock().unwrap();
    let values = VALUES.lock().unwrap();
    let constant = CONSTANT.lock().unwrap();
    assert_eq!(nodes.len(), values.len());
    assert_eq!(nodes.len(), constant.len());

    let a = unsafe { (*a).0 };
    assert!(a < nodes.len());
    assert!(constant[a]);
    values[a] != U256::ZERO
}

pub unsafe fn Fr_eq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Eq, to, a, b);
}

pub unsafe fn Fr_neq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Neq, to, a, b);
}

pub unsafe fn Fr_lt(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Lt, to, a, b);
}

pub unsafe fn Fr_gt(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Gt, to, a, b);
}

pub unsafe fn Fr_leq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Leq, to, a, b);
}

pub unsafe fn Fr_geq(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Geq, to, a, b);
}

pub unsafe fn Fr_lor(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Lor, to, a, b);
}

pub unsafe fn Fr_shl(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Shl, to, a, b);
}

pub unsafe fn Fr_shr(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Shr, to, a, b);
}

pub unsafe fn Fr_band(to: *mut FrElement, a: *const FrElement, b: *const FrElement) {
    binop(Operation::Band, to, a, b);
}
