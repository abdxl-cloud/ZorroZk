#![no_main]
sp1_zkvm::entrypoint!(entrypoint);

use sp1_zkvm::io;
use light_poseidon::{Poseidon, PoseidonBytesHasher};
use ark_bn254::Fr;
use shared::TransferWitness;  // shared struct

#[unsafe(no_mangle)]
pub fn entrypoint() {
    // Read the witness from the host (deserialized via Serde/bincode)
    let witness = io::read::<TransferWitness>();
    let old_sender    = witness.old_balance_sender;
    let old_receiver  = witness.old_balance_receiver;
    let amount        = witness.transfer_amount;

    // Enforce transfer constraints
    if old_sender < amount {
        panic!("Sender balance too low!");
    }
    let new_sender   = old_sender - amount;
    let new_receiver = old_receiver + amount;
    // Check sum conservation
    assert_eq!(old_sender + old_receiver, new_sender + new_receiver);

    // Prepare 32-byte arrays for each balance (big-endian)
    let mut old_sender_bytes   = [0u8; 32];
    let mut old_receiver_bytes = [0u8; 32];
    let mut new_sender_bytes   = [0u8; 32];
    let mut new_receiver_bytes = [0u8; 32];
    old_sender_bytes[24..32].copy_from_slice(&old_sender.to_be_bytes());
    old_receiver_bytes[24..32].copy_from_slice(&old_receiver.to_be_bytes());
    new_sender_bytes[24..32].copy_from_slice(&new_sender.to_be_bytes());
    new_receiver_bytes[24..32].copy_from_slice(&new_receiver.to_be_bytes());

    // Initialize a Poseidon hasher for 2 inputs (Circom-compatible)
    let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
    let commit_old_sender   = poseidon.hash_bytes_be(&[&old_sender_bytes,   &witness.rand_sender_old]).unwrap();
    let commit_old_receiver = poseidon.hash_bytes_be(&[&old_receiver_bytes, &witness.rand_receiver_old]).unwrap();
    let commit_new_sender   = poseidon.hash_bytes_be(&[&new_sender_bytes,   &witness.rand_sender_new]).unwrap();
    let commit_new_receiver = poseidon.hash_bytes_be(&[&new_receiver_bytes, &witness.rand_receiver_new]).unwrap();

    // Output (commit) the four public values (each 32 bytes)
    io::commit(&commit_old_sender);
    io::commit(&commit_old_receiver);
    io::commit(&commit_new_sender);
    io::commit(&commit_new_receiver);
}
