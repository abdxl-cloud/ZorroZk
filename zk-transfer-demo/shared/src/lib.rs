use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct TransferWitness {
    pub old_balance_sender: u64,
    pub old_balance_receiver: u64,
    pub transfer_amount: u64,
    pub rand_sender_old: [u8; 32],
    pub rand_receiver_old: [u8; 32],
    pub rand_sender_new: [u8; 32],
    pub rand_receiver_new: [u8; 32],
}
