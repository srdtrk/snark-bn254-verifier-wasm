## Getting started
### Step 1.
In theory, the proving key is generated in `go/groth16.go` and the verifying key is generated in `go/plonk_vk.go`. 

But the current go code isn't generating the keys correctly and they have to be sourced from the vk/ folder.

### Step 2.
Compile the wasm module and run the server:
```
wasm-pack build --target web && python -m http.server 8000
```

You can then pass the .bin files from the examples/binaries/ folder to the wasm module to verify the proofs.

