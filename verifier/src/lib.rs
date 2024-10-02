#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]

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

// use sp1_sdk::{proto::network::ProofMode, SP1ProofWithPublicValues};
// use num_bigint::BigUint;

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
/// Test
extern {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
/// WASM to verify a groth16 proof
pub fn verify_groth16_wasm(proof: &[u8], vk: &[u8], public_inputs: &[u8]) -> Result<bool, JsValue> {

    alert(&format!("Public inputs length: {}", public_inputs.len()));

    let frs: Vec<Fr> = public_inputs
        .chunks_exact(32)
        .map(Fr::from_slice)
        .collect::<Result<_, _>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid public input: {}", e)))?;

    let proof = load_groth16_proof_from_bytes(proof)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;
        
    let vk = load_groth16_verifying_key_from_bytes(vk)
        .map_err(|e| JsValue::from_str(&format!("Invalid verification key: {}", e)))?;

    Ok(verify_groth16(&vk, &proof, &frs).is_ok())
}

#[wasm_bindgen]
/// WASM to verify a plonk proof
pub fn verify_plonk_wasm(proof: &[u8], vk: &[u8], public_inputs: &[u8]) -> Result<bool, JsValue> {
    let frs: Vec<Fr> = public_inputs
        .chunks_exact(32)
        .map(Fr::from_slice)
        .collect::<Result<_, _>>()
        .map_err(|e| JsValue::from_str(&format!("Invalid public input: {}", e)))?;

    let proof = load_plonk_proof_from_bytes(proof)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;

    let vk = load_plonk_verifying_key_from_bytes(vk)
        .map_err(|e| JsValue::from_str(&format!("Invalid verification key: {}", e)))?;

    Ok(verify_plonk(&vk, &proof, &frs).is_ok())
}

/*
#[wasm_bindgen]
/// WASM to verify a proof using SP1 to read proof and public inputs
pub fn verify_proof(proof_file: &str, method: ProofMode) -> Result<bool, JsValue> {
    // Load the saved proof and convert it to the specified proof mode
    let (raw_proof, public_inputs) = SP1ProofWithPublicValues::load(proof_file)
        .map(|sp1_proof_with_public_values| match method {
            ProofMode::Groth16 => {
                let proof = sp1_proof_with_public_values
                    .proof
                    .try_as_groth_16()
                    .unwrap();
                (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
            }
            ProofMode::Plonk => {
                let proof = sp1_proof_with_public_values.proof.try_as_plonk().unwrap();
                (hex::decode(proof.raw_proof).unwrap(), proof.public_inputs)
            }
            _ => panic!("Invalid proof mode. Use 'groth16' or 'plonk'."),
        })
        .expect("Failed to load proof");

    // Convert public inputs to byte representations
    let vkey_hash = BigUint::from_str_radix(&public_inputs[0], 10)
        .unwrap()
        .to_bytes_be();
    let committed_values_digest = BigUint::from_str_radix(&public_inputs[1], 10)
        .unwrap()
        .to_bytes_be();

    // Call the appropriate verification function based on the method
    match method {
        ProofMode::Groth16 => verify_groth16_wasm(&raw_proof, &vkey_hash, &committed_values_digest),
        ProofMode::Plonk => verify_plonk_wasm(&raw_proof, &vkey_hash, &committed_values_digest),
        _ => Err(JsValue::from_str("Invalid proof mode")),
    }
}
*/