import React, { useState, useEffect } from 'react';
import { verify_groth16_wasm, verify_plonk_wasm } from 'snark-bn254-verifier';

const SnarkVerifier: React.FC = () => {
  const [groth16Result, setGroth16Result] = useState<boolean | null>(null);
  const [plonkResult, setPlonkResult] = useState<boolean | null>(null);
  const [isWasmLoaded, setIsWasmLoaded] = useState(false);

  useEffect(() => {
    const loadWasm = async () => {
      try {
        // Check if there's an initialization function
        // snarkBn254Verifier.default();
        setIsWasmLoaded(true);
      } catch (error) {
        console.error('Failed to load WASM module:', error);
      }
    };

    loadWasm();
  }, []);

  const handleVerifyGroth16 = () => {
    if (!isWasmLoaded) {
      console.error('WASM module not loaded');
      return;
    }

    // In a real application, you'd get these values from user input or an API
    const proof = new Uint8Array([1, 2, 3, 4]);
    const vk = new Uint8Array([5, 6, 7, 8]);
    const publicInputs = new Uint8Array([9, 10, 11, 12]);

    try {
      const result = verify_groth16_wasm(proof, vk, publicInputs);
      setGroth16Result(result === true);
    } catch (error) {
      console.error('Error verifying Groth16:', error);
      setGroth16Result(false);
    }
  };

  const handleVerifyPlonk = () => {
    if (!isWasmLoaded) {
      console.error('WASM module not loaded');
      return;
    }

    // In a real application, you'd get these values from user input or an API
    const proof = new Uint8Array([1, 2, 3, 4]);
    const vk = new Uint8Array([5, 6, 7, 8]);
    const publicInputs = new Uint8Array([9, 10, 11, 12]);

    try {
      const result = verify_plonk_wasm(proof, vk, publicInputs);
      setPlonkResult(result === true);
    } catch (error) {
      console.error('Error verifying PLONK:', error);
      setPlonkResult(false);
    }
  };

  return (
    <div>
      <h1>SNARK Verifier</h1>
      <button onClick={handleVerifyGroth16} disabled={!isWasmLoaded}>
        Verify Groth16
      </button>
      {groth16Result !== null && (
        <p>Groth16 Verification Result: {groth16Result ? 'Valid' : 'Invalid'}</p>
      )}
      <button onClick={handleVerifyPlonk} disabled={!isWasmLoaded}>
        Verify PLONK
      </button>
      {plonkResult !== null && (
        <p>PLONK Verification Result: {plonkResult ? 'Valid' : 'Invalid'}</p>
      )}
    </div>
  );
};

export default SnarkVerifier;