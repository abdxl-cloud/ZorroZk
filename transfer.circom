pragma circom 2.0.0;

include "circomlib/circuits/poseidon.circom";  // Poseidon hash library

template PrivateTransfer() {
    // Public inputs (to be verified on-chain)
    signal output commit_old_sender;
    signal output commit_old_receiver;
    signal output commit_new_sender;
    signal output commit_new_receiver;

    // Private inputs (witnesses)
    signal input old_balance_sender;
    signal input old_balance_receiver;
    signal input transfer_amount;
    signal input rand_sender_old;    // blinding for sender's old balance
    signal input rand_receiver_old;  // blinding for receiver's old balance
    signal input rand_sender_new;    // blinding for sender's new balance
    signal input rand_receiver_new;  // blinding for receiver's new balance

    // Compute new balances
    var new_balance_sender = old_balance_sender - transfer_amount;
    var new_balance_receiver = old_balance_receiver + transfer_amount;

    // Enforce no underflow/negative:
    old_balance_sender >= transfer_amount;

    // Poseidon hash inputs need to be in field. Ensure inputs fit field (here assume 64-bit balances).
    component poseidon1 = Poseidon(2);
    component poseidon2 = Poseidon(2);
    component poseidon3 = Poseidon(2);
    component poseidon4 = Poseidon(2);

    // Compute commitments using Poseidon: Poseidon(balance, rand)
    poseidon1.inputs[0] <-- old_balance_sender;
    poseidon1.inputs[1] <-- rand_sender_old;
    commit_old_sender <-- poseidon1.out;

    poseidon2.inputs[0] <-- old_balance_receiver;
    poseidon2.inputs[1] <-- rand_receiver_old;
    commit_old_receiver <-- poseidon2.out;

    poseidon3.inputs[0] <-- new_balance_sender;
    poseidon3.inputs[1] <-- rand_sender_new;
    commit_new_sender <-- poseidon3.out;

    poseidon4.inputs[0] <-- new_balance_receiver;
    poseidon4.inputs[1] <-- rand_receiver_new;
    commit_new_receiver <-- poseidon4.out;

    // Enforce conservation: old_s + old_r = new_s + new_r
    new_balance_sender + new_balance_receiver === old_balance_sender + old_balance_receiver;
}

component main = PrivateTransfer();
