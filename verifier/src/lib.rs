#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

//! This crate provides verifiers for Groth16 and Plonk zero-knowledge proofs.

use bn::Fr;
use groth16::{
    error::Groth16Error, load_groth16_proof_from_bytes, load_groth16_verifying_key_from_bytes,
    verify_groth16,
};
use plonk::{
    error::PlonkError, load_plonk_proof_from_bytes, load_plonk_verifying_key_from_bytes,
    verify_plonk,
};
use wasm_bindgen::prelude::*;

mod constants;
mod converter;
mod error;
mod groth16;
mod hash_to_field;
mod plonk;
mod transcript;

// #[global_allocator]
// static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
/// WASM to verify a groth16 proof
pub fn verify_groth16_wasm(proof: Vec<u8>, vk: Vec<u8>, public_inputs: Vec<u8>) -> bool {
    println!("proof: {:?}", proof);
    let frs: Vec<Fr> = public_inputs.chunks(8).map(|slice| Fr::from_slice(slice).unwrap()).collect();
    let proof = load_groth16_proof_from_bytes(&proof).unwrap();
    let vk = load_groth16_verifying_key_from_bytes(&vk).unwrap();

    verify_groth16(&vk, &proof, &frs).is_ok()
}

#[wasm_bindgen]
/// WASM to verify a plonk proof
pub fn verify_plonk_wasm(proof: &[u8], vk: &[u8], public_inputs: &[u8]) -> bool {
    let frs: Vec<Fr> = public_inputs.chunks(8).map(|slice| Fr::from_slice(slice).unwrap()).collect();
    let proof = load_plonk_proof_from_bytes(proof).unwrap();
    let vk = load_plonk_verifying_key_from_bytes(vk).unwrap();

    verify_plonk(&vk, &proof, &frs).is_ok()
}