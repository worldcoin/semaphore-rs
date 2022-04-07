#![warn(clippy::all, clippy::pedantic, clippy::cargo, clippy::nursery)]

use color_eyre::Result as EyreResult;
use log::Level;
use plonky2::{
    field::field_types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, Witness},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, KeccakGoldilocksConfig, PoseidonGoldilocksConfig},
        proof::{CompressedProofWithPublicInputs, ProofWithPublicInputs},
    },
};
use rand::Rng as _;
use std::{iter::once, sync::atomic::Ordering, time::Instant};
use tracing::{info, trace};

type Rng = rand_pcg::Mcg128Xsl64;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
// type C = KeccakGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;
type Builder = CircuitBuilder<F, D>;
type Proof = ProofWithPublicInputs<F, C, D>;

// https://arxiv.org/pdf/1509.09308.pdf
// https://en.wikipedia.org/wiki/Freivalds%27_algorithm ?

#[derive(Clone, Debug, PartialEq)]
pub struct Options {
    /// Bench over increasing output sizes
    //#[structopt(long)]
    pub bench: bool,

    /// The size of the input layer
    //#[structopt(long, default_value = "1000")]
    pub input_size: usize,

    /// The size of the output layer
    //#[structopt(long, default_value = "1000")]
    pub output_size: usize,

    /// Coefficient bits
    //#[structopt(long, default_value = "16")]
    pub coefficient_bits: usize,

    /// Number of wire columns
    //#[structopt(long, default_value = "400")]
    pub num_wires: usize,

    /// Number of routed wire columns
    //#[structopt(long, default_value = "400")]
    pub num_routed_wires: usize,

    /// Number of constants per constant gate
    //#[structopt(long, default_value = "90")]
    pub constant_gate_size: usize,
}

fn to_field(value: i32) -> F {
    if value >= 0 {
        F::from_canonical_u32(value as u32)
    } else {
        -F::from_canonical_u32(-value as u32)
    }
}

/// Compute the inner product of `coefficients` and `input`
fn dot(builder: &mut Builder, coefficients: &[i32], input: &[Target]) -> Target {
    // TODO: Compare this accumulator approach against a batch sum.
    assert_eq!(coefficients.len(), input.len());
    // builder.push_context(Level::Info, "dot");
    let mut sum = builder.zero();
    for (&coefficient, &input) in coefficients.iter().zip(input) {
        let coefficient = to_field(coefficient);
        sum = builder.mul_const_add(coefficient, input, sum);
    }
    // builder.pop_context();
    sum
}

fn full(builder: &mut Builder, coefficients: &[i32], input: &[Target]) -> Vec<Target> {
    let input_size = input.len();
    let output_size = coefficients.len() / input_size;
    assert_eq!(coefficients.len(), input_size * output_size);

    builder.push_context(Level::Info, "full");
    let mut output = Vec::with_capacity(output_size);
    for coefficients in coefficients.chunks_exact(input_size) {
        output.push(dot(builder, coefficients, input));
    }
    builder.pop_context();
    output
}

struct Circuit {
    inputs:  Vec<Target>,
    outputs: Vec<Target>,
    data:    CircuitData<F, C, D>,
}

impl Circuit {
    fn build(options: &Options, coefficients: &[i32]) -> Circuit {
        assert_eq!(coefficients.len(), options.input_size * options.output_size);
        info!(
            "Building circuit for for {}x{} matrix-vector multiplication",
            options.input_size, options.output_size
        );

        let config = CircuitConfig {
            num_wires: options.num_wires,
            num_routed_wires: options.num_routed_wires,
            ..CircuitConfig::default()
        };
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Inputs
        builder.push_context(Level::Info, "Inputs");
        let inputs = builder.add_virtual_targets(options.input_size);
        inputs
            .iter()
            .for_each(|target| builder.register_public_input(*target));
        builder.pop_context();

        // Circuit
        let outputs = full(&mut builder, &coefficients, &inputs);
        outputs
            .iter()
            .for_each(|target| builder.register_public_input(*target));

        // Log circuit size
        builder.print_gate_counts(0);
        let data = builder.build::<C>();

        Self {
            inputs,
            outputs,
            data,
        }
    }

    fn prove(&self, input: &[i32]) -> EyreResult<Proof> {
        info!("Proving {} size input", input.len());
        let mut pw = PartialWitness::new();
        for (&target, &value) in self.inputs.iter().zip(input) {
            pw.set_target(target, to_field(value));
        }
        let proof = self.data.prove(pw).unwrap();
        // let compressed = proof.clone().compress(&self.data.common).unwrap();
        // let proof_size = compressed.to_bytes().map_any()?.len();
        // info!("Proof size: {proof_size}");
        Ok(proof)
    }

    fn verify(&self, proof: &Proof) -> EyreResult<()> {
        info!(
            "Verifying proof with {} public inputs",
            proof.public_inputs.len()
        );
        self.data.verify(proof.clone()).unwrap();
        Ok(())
    }
}

pub async fn main(mut rng: Rng, mut options: Options) -> EyreResult<()> {
    info!(
        "Computing proof for {}x{} matrix-vector multiplication",
        options.input_size, options.output_size
    );

    println!(
        "input_size,output_size,build_time_s,proof_time_s,proof_mem_b,proof_size_b,verify_time_s"
    );
    let output_sizes: Box<dyn Iterator<Item = usize>> = if options.bench {
        Box::new((1..).map(|n| n * 1000))
    } else {
        Box::new(once(options.output_size))
    };
    for output_size in output_sizes {
        options.output_size = output_size;

        // Coefficients
        let quantize_coeff = |c: i32| c % (1 << options.coefficient_bits);
        let coefficients: Vec<i32> = (0..options.input_size * options.output_size)
            .map(|_| quantize_coeff(rng.gen()))
            .collect();
        let now = Instant::now();
        let circuit = Circuit::build(&options, &coefficients);
        let circuit_build_time = now.elapsed();

        // Set witness for proof
        let input_values = (0..options.input_size as i32)
            .into_iter()
            .map(|_| rng.gen())
            .collect::<Vec<_>>();
        let now = Instant::now();
        let proof = circuit.prove(&input_values)?;
        let proof_time = now.elapsed();

        // Verifying
        let now = Instant::now();
        circuit.verify(&proof)?;
        let verify_time = now.elapsed();

        println!(
            "{},{},{},{},{}",
            options.input_size,
            options.output_size,
            circuit_build_time.as_secs_f64(),
            proof_time.as_secs_f64(),
            verify_time.as_secs_f64()
        );
    }

    Ok(())
}
