use bn::AffineG1;

use crate::{
    converter::{
        unchecked_compressed_x_to_g1_point, unchecked_compressed_x_to_g2_point,
        uncompressed_bytes_to_g1_point, uncompressed_bytes_to_g2_point,
    },
    groth16::{Groth16G1, Groth16G2, Groth16Proof, Groth16VerifyingKey, PedersenVerifyingKey},
};

use super::error::Groth16Error;
use crate::wasm_bindgen;

#[wasm_bindgen]
/// Test
extern {
    #[wasm_bindgen(js_namespace = console)]
    pub fn log(s: &str);
}

pub(crate) fn load_groth16_proof_from_bytes(buffer: &[u8]) -> Result<Groth16Proof, Groth16Error> {

    if buffer.len() < 256 {
        return Err(Groth16Error::PrepareInputsFailed);
    }

    let ar = uncompressed_bytes_to_g1_point(&buffer[..64])?;
    let bs = uncompressed_bytes_to_g2_point(&buffer[64..192])?;
    let krs = uncompressed_bytes_to_g1_point(&buffer[192..256])?;

    Ok(Groth16Proof {
        ar,
        bs,
        krs,
        commitments: Vec::new(),
        commitment_pok: AffineG1::one(),
    })

}

pub(crate) fn load_groth16_verifying_key_from_bytes(
    buffer: &[u8],
) -> Result<Groth16VerifyingKey, Groth16Error> {

    // log(&format!("buffer: {:?}", buffer));

    if buffer.len() < 292 {
        log(&format!("buffer.len() < 292"));
        return Err(Groth16Error::PrepareInputsFailed);
    }

    log(&format!("caling unchecked_compressed_x_to_()..."));

    let g1_alpha = unchecked_compressed_x_to_g1_point(&buffer[..32])?;
    log(&format!("g1_alpha: {:?}", g1_alpha));
    let g1_beta = unchecked_compressed_x_to_g1_point(&buffer[32..64])?;
    log(&format!("g1_beta: {:?}", g1_beta));
    let g2_beta = unchecked_compressed_x_to_g2_point(&buffer[64..128])?;
    log(&format!("g2_beta: {:?}", g2_beta));
    let g2_gamma = unchecked_compressed_x_to_g2_point(&buffer[128..192])?;
    log(&format!("g2_gamma: {:?}", g2_gamma));
    let g1_delta = unchecked_compressed_x_to_g1_point(&buffer[192..224])?;
    log(&format!("g1_delta: {:?}", g1_delta));
    let g2_delta = unchecked_compressed_x_to_g2_point(&buffer[224..288])?;
    log(&format!("g2_delta: {:?}", g2_delta));

    let num_k = u32::from_be_bytes([buffer[288], buffer[289], buffer[290], buffer[291]]);
    let mut k = Vec::new();
    let mut offset = 292;

    // TODO: Add additional check for buffer inside the function.
    if buffer.len() < (offset + 32 * num_k as usize) {
        return Err(Groth16Error::PrepareInputsFailed);
    }

    for _ in 0..num_k {
        let point = unchecked_compressed_x_to_g1_point(&buffer[offset..offset + 32])?;
        k.push(point);
        offset += 32;
    }

    let num_of_array_of_public_and_commitment_committed = u32::from_be_bytes([
        buffer[offset],
        buffer[offset + 1],
        buffer[offset + 2],
        buffer[offset + 3],
    ]);
    offset += 4;
    for _ in 0..num_of_array_of_public_and_commitment_committed {
        let num = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]);
        offset += 4;
        for _ in 0..num {
            offset += 4;
        }
    }

    let commitment_key_g = unchecked_compressed_x_to_g2_point(&buffer[offset..offset + 64])?;
    let commitment_key_g_root_sigma_neg =
        unchecked_compressed_x_to_g2_point(&buffer[offset + 64..offset + 128])?;

    Ok(Groth16VerifyingKey {
        g1: Groth16G1 {
            alpha: g1_alpha,
            beta: -g1_beta,
            delta: g1_delta,
            k,
        },
        g2: Groth16G2 {
            beta: -g2_beta,
            gamma: g2_gamma,
            delta: g2_delta,
        },
        commitment_key: PedersenVerifyingKey {
            g: commitment_key_g,
            g_root_sigma_neg: commitment_key_g_root_sigma_neg,
        },
        public_and_commitment_committed: vec![vec![0u32; 0]],
    })
}
