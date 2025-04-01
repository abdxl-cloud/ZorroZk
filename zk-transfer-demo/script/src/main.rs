use sp1_sdk::{include_elf, ProverClient, SP1Stdin, HashableKey};
use sp1_verifier::{Groth16Verifier, GROTH16_VK_BYTES};
use hex;
use shared::TransferWitness;
use bincode; // used to serialize public values

// Embed the guest ELF using include_elf! macro
const GUEST_ELF: &[u8] = include_elf!("program");

fn main() {
    // Prepare the witness (private input)
    let witness = TransferWitness {
        old_balance_sender:   100,
        old_balance_receiver: 50,
        transfer_amount:      30,
        rand_sender_old:      [0x01; 32],
        rand_receiver_old:    [0x02; 32],
        rand_sender_new:      [0x03; 32],
        rand_receiver_new:    [0x04; 32],
    };

    // Create an SP1Stdin and write the witness (uses Serde/bincode)
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);

    // Initialize the SP1 Prover client (configured via environment)
    let client = ProverClient::from_env();

    // --- Step 1: Execute the guest program (for testing) ---
    let (mut public_values, exec_report) = client.execute(GUEST_ELF, &stdin)
        .run()
        .expect("Execution failed");
    println!("Executed program in {} cycles",
             exec_report.total_instruction_count() + exec_report.total_syscall_count());
    // Read the four 32-byte public outputs in order
    let c1 = public_values.read::<[u8; 32]>();
    let c2 = public_values.read::<[u8; 32]>();
    let c3 = public_values.read::<[u8; 32]>();
    let c4 = public_values.read::<[u8; 32]>();
    println!("Commitment (old sender):    0x{}", hex::encode(c1));
    println!("Commitment (old receiver):  0x{}", hex::encode(c2));
    println!("Commitment (new sender):    0x{}", hex::encode(c3));
    println!("Commitment (new receiver):  0x{}", hex::encode(c4));

    // --- Step 2: Generate the Groth16 proof ---
    // Remove the .expect here because client.setup returns a tuple directly.
    let (pk, vk) = client.setup(GUEST_ELF);
    let proof = client.prove(&pk, &stdin)
        .groth16()  // choose Groth16 proof system
        .run()
        .expect("Proof generation failed");
    println!("Proof generated ({} bytes)", proof.bytes().len());

    // --- Step 3: Verify the proof locally ---
    let proof_bytes = proof.bytes();
    // Serialize public_values into bytes using bincode (so we get &[u8])
    let public_inputs: Vec<u8> = bincode::serialize(&proof.public_values)
        .expect("Public inputs serialization failed");
    let vk_hash_string = vk.bytes32(); // Get the verifying key hash (32-byte string)
    let verify_ok = Groth16Verifier::verify(&proof_bytes, &public_inputs,
                                             vk_hash_string.as_str(), *GROTH16_VK_BYTES)
                      .is_ok();
    println!("Proof is valid: {}", verify_ok);
    println!("Verifying key hash: {}", vk_hash_string);
}