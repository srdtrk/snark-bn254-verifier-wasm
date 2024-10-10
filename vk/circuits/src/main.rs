
use std::fs;

use sp1_sdk::install::{install_circuit_artifacts, install_circuit_artifacts_dir};
use std::path::PathBuf;

fn install_artifacts(build_dir: PathBuf) {
    install_circuit_artifacts(build_dir.clone());
}

fn main() {
    println!("Downloading the artifacts...");
    let build_dir = install_circuit_artifacts_dir();
    println!("build_dir: {}", build_dir.display());
    install_artifacts(build_dir);

    println!("Copying verification key files...");

    let home_dir = std::env::var("HOME").expect("HOME environment variable not set");
    let source_dir = PathBuf::from(home_dir).join(".sp1/circuits/v2.0.0");
    let dest_dir = PathBuf::from("../../vk");

    let files_to_copy = ["plonk_vk.bin", "groth16_vk.bin"];

    for file in files_to_copy.iter() {
        let source_path = source_dir.join(file);
        let dest_path = dest_dir.join(file);

        match fs::copy(&source_path, &dest_path) {
            Ok(_) => println!("Successfully copied {} to {}", file, dest_path.display()),
            Err(e) => eprintln!("Failed to copy {} ({} -> {}): {}", file, source_path.display(), dest_path.display(), e),
        }
    }

    println!("Finished copying verification key files.");

}
