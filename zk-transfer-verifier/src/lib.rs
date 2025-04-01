use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use sp1_solana::{verify_proof, GROTH16_VK_2_0_0_BYTES};

/// Example instruction data, carrying the proof and public inputs (serialized).
#[derive(BorshSerialize, BorshDeserialize)]
pub enum InstructionData {
    /// Instruction variant that includes a Groth16 proof + public inputs
    VerifyZkProof {
        proof: Vec<u8>,
        public_inputs: Vec<u8>,
    },
}

/// Example account data storing a 32-byte commitment.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct CommitmentAccount {
    pub commitment: [u8; 32],
}

/// Solana program entrypoint macro
entrypoint!(process_instruction);

/// Main program logic
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    // 1) Deserialize the instruction
    let instruction = InstructionData::try_from_slice(instruction_data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // 2) Prepare account iteration
    let account_info_iter = &mut accounts.iter();

    // 3) Match on the instruction variant
    match instruction {
        InstructionData::VerifyZkProof { proof, public_inputs } => {
            // Expect two writable accounts: sender & receiver (or old & new, etc.)
            let sender_info = next_account_info(account_info_iter)?;
            let receiver_info = next_account_info(account_info_iter)?;

            // Ensure they are owned by this program
            if sender_info.owner != program_id || receiver_info.owner != program_id {
                msg!("Error: accounts not owned by this program");
                return Err(ProgramError::IncorrectProgramId);
            }

            // For a private transfer scenario, we typically have 4 commitments in public_inputs:
            //   [old_sender, old_receiver, new_sender, new_receiver]
            // each 32 bytes => 128 total
            if public_inputs.len() != 128 {
                msg!("Error: expecting exactly 128 bytes of public inputs (4 commitments)");
                return Err(ProgramError::InvalidInstructionData);
            }

            let old_sender_commitment   = &public_inputs[0..32];
            let old_receiver_commitment = &public_inputs[32..64];
            let new_sender_commitment   = &public_inputs[64..96];
            let new_receiver_commitment = &public_inputs[96..128];

            // This is the verifying key hash from your off-chain proof generation (replace as needed).
            const MY_VKEY_HASH: &str = "0083e8e370d7f0d1c463337f76c9a60b62ad7cc54c89329107c92c1e62097872";

            // 4) Verify the proof on-chain
            verify_proof(
                &proof,
                &public_inputs,
                MY_VKEY_HASH,
                GROTH16_VK_2_0_0_BYTES, // from sp1-solana
            ).map_err(|err| {
                msg!("Proof verification failed: {:?}", err);
                ProgramError::InvalidInstructionData
            })?;
            msg!("Proof verified successfully!");

            // 5) Load the current commitments from account data
            let mut sender_data = sender_info.try_borrow_mut_data()?;
            let mut receiver_data = receiver_info.try_borrow_mut_data()?;

            // Deserialize each account as CommitmentAccount
            let mut sender_acc = CommitmentAccount::try_from_slice(&sender_data)
                .map_err(|_| ProgramError::InvalidAccountData)?;
            let mut receiver_acc = CommitmentAccount::try_from_slice(&receiver_data)
                .map_err(|_| ProgramError::InvalidAccountData)?;

            // Check the old commitments match what's stored
            if sender_acc.commitment != old_sender_commitment {
                msg!("Mismatch: on-chain sender commitment != proof's old sender commitment");
                return Err(ProgramError::InvalidAccountData);
            }
            if receiver_acc.commitment != old_receiver_commitment {
                msg!("Mismatch: on-chain receiver commitment != proof's old receiver commitment");
                return Err(ProgramError::InvalidAccountData);
            }

            // 6) Update the commitments to the new ones
            sender_acc.commitment.copy_from_slice(new_sender_commitment);
            receiver_acc.commitment.copy_from_slice(new_receiver_commitment);

            // 7) Write updated data back to the accounts
            sender_acc.serialize(&mut *sender_data)?;
            receiver_acc.serialize(&mut *receiver_data)?;

            msg!("Commitments updated successfully!");
        }
    }

    Ok(())
}
