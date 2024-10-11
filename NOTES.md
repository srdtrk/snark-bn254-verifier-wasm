# SP1 BN254 VK & Proof Generation

Here are some notes I've gathered on how SP1 generates the VK and proof for the BN254 curve.

Both SP1's prover functions `build_plonk_bn254_artifacts_with_dummy()` and `build_groth16_bn254_artifacts_with_dummy()` rely on the [`dummy_proof()`](https://github.com/succinctlabs/sp1/blob/db08c629584bd014b7ef886b5c25d3130bd9b047/crates/prover/src/build.rs#L121) function to generate the template verification key and proof that are passed to `build_constraints_and_witness(StarkVerifyingKey, ShardProof) -> (Constraint, Witness)`.

`dummy_proof()` uses the SP1 ZKVM (`riscv32im-succinct-zkvm-elf`) to generate a dummy proof before building the circuit.

[build_*_bn254_artifacts()](https://github.com/succinctlabs/sp1/blob/db08c629584bd014b7ef886b5c25d3130bd9b047/crates/prover/src/build.rs#L53) build_constraints_and_witness() then returns the constraints and witness that will be used to generate the circuit.

[`Groth16Bn254Prover()`](https://github.com/succinctlabs/sp1/blob/db08c629584bd014b7ef886b5c25d3130bd9b047/crates/recursion/gnark-ffi/src/groth16_bn254.rs#L59) (GNARK's FFI) is then called with the constraints and witness to generate the proving key and verification key (groth16_vk.bin, plonk_vk.bin).

`vk/circuits/src/main.rs` is used to download the plonk_vk.bin and groth16_vk.bin files in the `vk` folder, by calling the `install_circuit_artifacts()` function from the [sp1-sdk](https://github.com/succinctlabs/sp1-sdk).



