#![deny(rustdoc::broken_intra_doc_links)]
#![deny(missing_debug_implementations)]

//! This crate provides verifiers for Groth16 and Plonk zero-knowledge proofs.
use sp1_sdk::{SP1ProofWithPublicValues};

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
use serde_json::Value;
use std::io::Read;
use num_bigint::BigUint;
use num_traits::Num;
use serde_json;
use hex;

// see vk/circuits/src/main.rs
const PLONK_VK_BYTES: &[u8] = include_bytes!("../../vk/plonk_vk.bin");
const GROTH16_VK_BYTES: &[u8] = include_bytes!("../../vk/groth16_vk.bin");

mod constants;
mod converter;
mod error;
mod groth16;
mod hash_to_field;
mod plonk;
mod transcript;

#[wasm_bindgen]
#[derive(Debug, Clone, Copy)]
pub enum ProofMode {
    Groth16,
    Plonk,
}


#[wasm_bindgen]
/// Test
extern {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

// #[wasm_bindgen]
/// WASM to verify a groth16 proof
pub fn verify_groth16_wasm(proof: &[u8], vk: &[u8], public_inputs: &[Fr]) -> Result<bool, JsValue> {
    let proof = load_groth16_proof_from_bytes(proof)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;
        
    let vk = load_groth16_verifying_key_from_bytes(vk)
        .map_err(|e| JsValue::from_str(&format!("Invalid verification key: {}", e)))?;

    Ok(verify_groth16(&vk, &proof, public_inputs).is_ok())
}


// #[wasm_bindgen]
/// WASM to verify a plonk proof
pub fn verify_plonk_wasm(proof: &[u8], vk: &[u8], public_inputs: &[Fr]) -> Result<bool, JsValue> {
    let proof = load_plonk_proof_from_bytes(proof)
        .map_err(|e| JsValue::from_str(&format!("Invalid proof: {}", e)))?;

    let vk = load_plonk_verifying_key_from_bytes(vk)
        .map_err(|e| JsValue::from_str(&format!("Invalid verification key: {}", e)))?;

    Ok(verify_plonk(&vk, &proof, public_inputs).is_ok())
}

#[wasm_bindgen]
/// WASM to verify a proof using SP1 to read proof and public inputs
pub fn verify_proof(contents: &[u8], method: ProofMode) -> Result<bool, JsValue> {

    // Load the saved proof and convert it to the specified proof mode
    // Passing the bytes directly instead of SP1ProofWithPublicValues::load()
    let sp1_proof_with_public_values: SP1ProofWithPublicValues = bincode::deserialize(contents)
        .expect("Failed to deserialize proof.");
    let (raw_proof, public_inputs) = match method {
        ProofMode::Groth16 => {
            // log(&format!("Proof mode: Groth16"));
            let proof = sp1_proof_with_public_values
                .proof
                .try_as_groth_16()
                .map_or(Err(JsValue::from_str("Failed to get Groth16 proof")), |p| Ok(p))?;
            let raw_proof = hex::decode(&proof.raw_proof)
                .map_or(Err(JsValue::from_str("Failed to decode Groth16 proof hex")), |r| Ok(r))?;
            (raw_proof, proof.public_inputs)
        }
        ProofMode::Plonk => {
            // log(&format!("Proof mode: Plonk"));
            let proof = sp1_proof_with_public_values
                .proof
                .try_as_plonk()
                .map_or(Err(JsValue::from_str("Failed to get Plonk proof")), |p| Ok(p))?;
            let raw_proof = hex::decode(&proof.raw_proof)
                .map_or(Err(JsValue::from_str("Failed to decode Plonk proof hex")), |r| Ok(r))?;
            (raw_proof, proof.public_inputs)
        }
        _ => return Err(JsValue::from_str("Invalid proof mode. Use 'groth16' or 'plonk'.")),
    };

    // Convert public inputs to byte representations
    let vkey_hash = BigUint::from_str_radix(&public_inputs[0], 10)
        .unwrap()
        .to_bytes_be();
    let committed_values_digest = BigUint::from_str_radix(&public_inputs[1], 10)
        .unwrap()
        .to_bytes_be();

    let vkey_hash = Fr::from_slice(&vkey_hash).expect("Unable to read vkey_hash");
    let committed_values_digest = Fr::from_slice(&committed_values_digest)
        .expect("Unable to read committed_values_digest");

    // Read VK from the appropriate binary
    let vk_bytes = match method {
        ProofMode::Groth16 => GROTH16_VK_BYTES,
        ProofMode::Plonk => PLONK_VK_BYTES,
    };

    // Call the appropriate verification function based on the method
    match method {
        ProofMode::Groth16 => verify_groth16_wasm(&raw_proof, &vk_bytes,  &[vkey_hash, committed_values_digest]),
        ProofMode::Plonk => verify_plonk_wasm(&raw_proof, &vk_bytes, &[vkey_hash, committed_values_digest]),
        _ => Err(JsValue::from_str("Invalid proof mode")),
    }
}