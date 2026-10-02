use pinocchio::{account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey};

/// Container for a set of compact instructions.
///
/// This struct holds multiple compact instructions and provides
/// functionality to serialize them into a byte format.
pub struct CompactInstructions {
    /// Vector of individual compact instructions
    pub inner_instructions: Vec<CompactInstruction>,
}

/// Represents a single instruction in compact format.
///
/// Instead of storing full public keys, this format uses indexes
/// into a shared account list to reduce data size.
///
/// # Fields
/// * `program_id_index` - Index of the program ID in the account list
/// * `accounts` - Indexes of accounts used by this instruction
/// * `data` - Raw instruction data
#[derive(Debug, Clone)]
pub struct CompactInstruction {
    pub program_id_index: u8,
    pub accounts: Vec<u8>,
    pub data: Vec<u8>,
}

/// Reference version of CompactInstruction that borrows its data.
/// Used by the Execute hot path to avoid Vec<u8> allocations during parse
/// + decompress.
///
/// # Fields
/// * `program_id_index` - Index of the program ID in the account list
/// * `accounts` - Slice of account indexes
/// * `data` - Slice of instruction data
pub struct CompactInstructionRef<'a> {
    pub program_id_index: u8,
    pub accounts: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> CompactInstructionRef<'a> {
    /// Deserialize a CompactInstructionRef from bytes — zero-copy, the
    /// returned struct borrows from `bytes`.
    /// Format: [program_id_index: u8][num_accounts: u8][accounts...][data_len: u16][data...]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ProgramError> {
        if bytes.len() < 4 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let program_id_index = bytes[0];
        // The program-id index carries no flag bit — the program a CPI targets
        // is never a signer this program forwards. A byte with the high bit set
        // here is a client that packed an index above 127, which the flag bit
        // makes unrepresentable; reject it rather than silently masking it into
        // a different account.
        if program_id_index > MAX_ACCOUNT_INDEX {
            return Err(ProgramError::InvalidInstructionData);
        }
        let num_accounts = bytes[1] as usize;

        if bytes.len() < 2 + num_accounts + 2 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let accounts = &bytes[2..2 + num_accounts];
        let data_len_offset = 2 + num_accounts;
        let data_len =
            u16::from_le_bytes([bytes[data_len_offset], bytes[data_len_offset + 1]]) as usize;

        let data_start = data_len_offset + 2;
        if bytes.len() < data_start + data_len {
            return Err(ProgramError::InvalidInstructionData);
        }

        let data = &bytes[data_start..data_start + data_len];
        let rest = &bytes[data_start + data_len..];

        Ok((
            CompactInstructionRef {
                program_id_index,
                accounts,
                data,
            },
            rest,
        ))
    }

    /// Decompress into a full Instruction without cloning the instruction
    /// data. `account_infos` lifetime 'b is tracked separately from the
    /// instruction-data lifetime 'a.
    pub fn decompress<'b>(
        &self,
        account_infos: &'b [AccountInfo],
    ) -> Result<DecompressedInstructionRef<'a, 'b>, ProgramError> {
        if (self.program_id_index as usize) >= account_infos.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let program_id = account_infos[self.program_id_index as usize].key();

        let mut accounts: Vec<&AccountInfo> = Vec::with_capacity(self.accounts.len());
        let mut forward_signer: Vec<bool> = Vec::with_capacity(self.accounts.len());
        for &byte in self.accounts {
            let (index, forward) = decode_account_index(byte);
            if index >= account_infos.len() {
                return Err(ProgramError::InvalidInstructionData);
            }
            accounts.push(&account_infos[index]);
            forward_signer.push(forward);
        }

        Ok(DecompressedInstructionRef {
            program_id,
            accounts,
            forward_signer,
            data: self.data,
        })
    }
}

/// Zero-copy variant of DecompressedInstruction. `data` borrows from the
/// original instruction_data — no clone.
pub struct DecompressedInstructionRef<'a, 'b> {
    pub program_id: &'b Pubkey,
    pub accounts: Vec<&'b AccountInfo>,
    /// Parallel to `accounts`: whether the caller asked for that account's
    /// signer flag to be forwarded into the CPI. See
    /// [`ACCOUNT_INDEX_FORWARD_SIGNER`].
    pub forward_signer: Vec<bool>,
    pub data: &'a [u8],
}

/// Parse + return total bytes consumed (ref-based, no allocations for
/// account index bytes or instruction data).
pub fn parse_compact_instructions_ref_with_len<'a>(
    bytes: &'a [u8],
) -> Result<(Vec<CompactInstructionRef<'a>>, usize), ProgramError> {
    if bytes.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let num_instructions = bytes[0] as usize;
    if num_instructions > MAX_COMPACT_INSTRUCTIONS {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut instructions = Vec::with_capacity(num_instructions);
    let mut remaining = &bytes[1..];

    for _ in 0..num_instructions {
        let (ix, rest) = CompactInstructionRef::from_bytes(remaining)?;
        instructions.push(ix);
        remaining = rest;
    }

    let consumed = bytes.len() - remaining.len();
    Ok((instructions, consumed))
}

impl CompactInstructions {
    /// Serializes the compact instructions into bytes.
    ///
    /// The byte format is:
    /// 1. Number of instructions (u8)
    /// 2. For each instruction:
    ///    - Program ID index (u8)
    ///    - Number of accounts (u8)
    ///    - Account indexes (u8 array)
    ///    - Data length (u16 LE)
    ///    - Instruction data (bytes)
    ///
    /// # Returns
    /// * `Vec<u8>` - Serialized instruction data
    pub fn into_bytes(&self) -> Vec<u8> {
        // Lengths are encoded as u8 — values > 255 would silently truncate and corrupt
        // the instruction stream on deserialization. Enforce at runtime, not just debug.
        assert!(
            self.inner_instructions.len() <= 255,
            "instruction count exceeds u8 max"
        );
        let mut bytes = vec![self.inner_instructions.len() as u8];
        for ix in self.inner_instructions.iter() {
            assert!(ix.accounts.len() <= 255, "account count exceeds u8 max");
            bytes.push(ix.program_id_index);
            bytes.push(ix.accounts.len() as u8);
            bytes.extend(ix.accounts.iter());
            bytes.extend((ix.data.len() as u16).to_le_bytes());
            bytes.extend(ix.data.iter());
        }
        bytes
    }
}

impl CompactInstruction {
    /// Deserialize a CompactInstruction from bytes
    /// Format: [program_id_index: u8][num_accounts: u8][accounts...][data_len: u16][data...]
    pub fn from_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), ProgramError> {
        if bytes.len() < 4 {
            // Minimum: program_id(1) + num_accounts(1) + data_len(2)
            return Err(ProgramError::InvalidInstructionData);
        }

        let program_id_index = bytes[0];
        if program_id_index > MAX_ACCOUNT_INDEX {
            return Err(ProgramError::InvalidInstructionData);
        }
        let num_accounts = bytes[1] as usize;

        if bytes.len() < 2 + num_accounts + 2 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let accounts = bytes[2..2 + num_accounts].to_vec();
        let data_len_offset = 2 + num_accounts;
        let data_len =
            u16::from_le_bytes([bytes[data_len_offset], bytes[data_len_offset + 1]]) as usize;

        let data_start = data_len_offset + 2;
        if bytes.len() < data_start + data_len {
            return Err(ProgramError::InvalidInstructionData);
        }

        let data = bytes[data_start..data_start + data_len].to_vec();
        let rest = &bytes[data_start + data_len..];

        Ok((
            CompactInstruction {
                program_id_index,
                accounts,
                data,
            },
            rest,
        ))
    }

    /// Serialize this CompactInstruction to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        assert!(self.accounts.len() <= 255, "account count exceeds u8 max");
        let mut bytes = Vec::with_capacity(4 + self.accounts.len() + self.data.len());
        bytes.push(self.program_id_index);
        bytes.push(self.accounts.len() as u8);
        bytes.extend_from_slice(&self.accounts);
        bytes.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Decompress this compact instruction into a full Instruction using the provided accounts
    pub fn decompress<'a>(
        &self,
        account_infos: &'a [AccountInfo],
    ) -> Result<DecompressedInstruction<'a>, ProgramError> {
        // Validate program_id_index
        if (self.program_id_index as usize) >= account_infos.len() {
            return Err(ProgramError::InvalidInstructionData);
        }

        let program_id = account_infos[self.program_id_index as usize].key();

        // Validate all account indexes
        let mut accounts = Vec::with_capacity(self.accounts.len());
        for &index in &self.accounts {
            if (index as usize) >= account_infos.len() {
                return Err(ProgramError::InvalidInstructionData);
            }
            accounts.push(&account_infos[index as usize]);
        }

        Ok(DecompressedInstruction {
            program_id,
            accounts,
            data: self.data.clone(), // Clone data to avoid lifetime issues
        })
    }
}

/// Decompressed instruction ready for execution
pub struct DecompressedInstruction<'a> {
    pub program_id: &'a Pubkey,
    pub accounts: Vec<&'a AccountInfo>,
    pub data: Vec<u8>, // Owned data to avoid lifetime issues
}

// ─── Account index encoding ──────────────────────────────────────────────

/// Mask selecting the account index from an index byte.
pub const ACCOUNT_INDEX_MASK: u8 = 0x7f;

/// High bit of an index byte: forward this account's signer flag into the CPI.
///
/// Signer forwarding used to be implicit — every outer signer became a signer
/// of every inner instruction that referenced it, with nobody having said so.
/// That is how a session limited to 0.001 SOL could move 2 SOL out of the
/// paymaster's own wallet: the limits watch the vault, and the paymaster is not
/// the vault. Making it an opt-in bit puts the request inside the compact bytes,
/// which for a Secp256r1 authority are inside the signed payload — so the
/// passkey holder signs the elevation, rather than it being inferred.
///
/// Costs one bit: indices are capped at 127 rather than 255.
pub const ACCOUNT_INDEX_FORWARD_SIGNER: u8 = 0x80;

/// Highest addressable account index, given the flag bit.
pub const MAX_ACCOUNT_INDEX: u8 = ACCOUNT_INDEX_MASK;

/// Split an index byte into `(index, forward_signer)`.
#[inline]
pub fn decode_account_index(byte: u8) -> (usize, bool) {
    (
        (byte & ACCOUNT_INDEX_MASK) as usize,
        byte & ACCOUNT_INDEX_FORWARD_SIGNER != 0,
    )
}

// ─── Accounts hash ───────────────────────────────────────────────────────

/// Privilege byte hashed after each account key.
///
/// Binding the *runtime* flags, not the requested ones: these are what actually
/// authorise the inner CPI, so they are what the signature must cover. A relayer
/// that marks a referenced account writable, or adds a signature to it, after
/// the passkey signed changes this byte and invalidates the signature — noisy,
/// and safe.
#[inline]
pub fn account_flags(is_signer: bool, is_writable: bool) -> u8 {
    (is_signer as u8) | ((is_writable as u8) << 1)
}

/// The walk order the accounts hash is defined over, independent of where the
/// account data comes from: for each compact instruction, the program id first,
/// then every account it references, each contributing its 32-byte key followed
/// by its flags byte.
///
/// `push` appends one account by index and reports an out-of-range index. The
/// indirection exists because `AccountInfo` cannot be constructed off-chain, so
/// a host test could not otherwise exercise this ordering — and the ordering is
/// the part that silently drifts between the program and the two SDKs.
///
/// The forward-signer bit is masked off before lookup: it addresses no account
/// and must not change the digest.
pub fn accounts_hash_preimage_with<F>(
    compact_instructions: &[CompactInstructionRef<'_>],
    mut push: F,
) -> Result<Vec<u8>, ProgramError>
where
    F: FnMut(usize, &mut Vec<u8>) -> Result<(), ProgramError>,
{
    let mut preimage = Vec::with_capacity(compact_instructions.len() * 4 * 33);

    for ix in compact_instructions {
        let (program_idx, _) = decode_account_index(ix.program_id_index);
        push(program_idx, &mut preimage)?;
        for &byte in ix.accounts {
            let (idx, _) = decode_account_index(byte);
            push(idx, &mut preimage)?;
        }
    }

    Ok(preimage)
}

/// Build the preimage the accounts hash is taken over, reading privilege from
/// the runtime's own view of each account.
///
/// Split out from the hashing because the digest comes from a syscall that does
/// not exist on the host — which is why the two copies of this logic in
/// `immediate.rs` and `deferred.rs` had no test at all and were kept in sync by
/// a comment.
pub fn accounts_hash_preimage(
    accounts: &[AccountInfo],
    compact_instructions: &[CompactInstructionRef<'_>],
) -> Result<Vec<u8>, ProgramError> {
    accounts_hash_preimage_with(compact_instructions, |idx, preimage| {
        let acc = accounts
            .get(idx)
            .ok_or(ProgramError::InvalidInstructionData)?;
        preimage.extend_from_slice(acc.key().as_ref());
        preimage.push(account_flags(acc.is_signer(), acc.is_writable()));
        Ok(())
    })
}

/// SHA-256 of [`accounts_hash_preimage`].
///
/// Off-chain this returns a fixed sentinel — the syscall does not exist there.
/// Assert on the preimage in host tests, not on this.
pub fn compute_accounts_hash(
    accounts: &[AccountInfo],
    compact_instructions: &[CompactInstructionRef<'_>],
) -> Result<[u8; 32], ProgramError> {
    let preimage = accounts_hash_preimage(accounts, compact_instructions)?;

    #[allow(unused_assignments)]
    let mut hash = [0u8; 32];
    #[cfg(target_os = "solana")]
    unsafe {
        let parts = [preimage.as_slice()];
        pinocchio::syscalls::sol_sha256(parts.as_ptr() as *const u8, 1, hash.as_mut_ptr());
    }
    #[cfg(not(target_os = "solana"))]
    {
        hash = [0xAA; 32];
        let _ = preimage;
    }

    Ok(hash)
}

/// Maximum number of compact instructions per Execute call.
/// Prevents compute-unit exhaustion DoS.
pub const MAX_COMPACT_INSTRUCTIONS: usize = 16;

/// Parse multiple CompactInstructions from bytes
/// Format: [num_instructions: u8][instruction_0][instruction_1]...
pub fn parse_compact_instructions(bytes: &[u8]) -> Result<Vec<CompactInstruction>, ProgramError> {
    parse_compact_instructions_with_len(bytes).map(|(ixs, _)| ixs)
}

/// Parse + return total bytes consumed. Used by the Execute processor to
/// split the instruction data into the compact-instructions prefix and the
/// auth payload suffix without re-serializing.
pub fn parse_compact_instructions_with_len(
    bytes: &[u8],
) -> Result<(Vec<CompactInstruction>, usize), ProgramError> {
    if bytes.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let num_instructions = bytes[0] as usize;
    if num_instructions > MAX_COMPACT_INSTRUCTIONS {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut instructions = Vec::with_capacity(num_instructions);
    let mut remaining = &bytes[1..];

    for _ in 0..num_instructions {
        let (instruction, rest) = CompactInstruction::from_bytes(remaining)?;
        instructions.push(instruction);
        remaining = rest;
    }

    let consumed = bytes.len() - remaining.len();
    Ok((instructions, consumed))
}

/// Serialize multiple CompactInstructions to bytes
pub fn serialize_compact_instructions(instructions: &[CompactInstruction]) -> Vec<u8> {
    let compact_instructions = CompactInstructions {
        inner_instructions: instructions.to_vec(),
    };
    compact_instructions.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compact_instruction_serialization() {
        let ix = CompactInstruction {
            program_id_index: 0,
            accounts: vec![1, 2, 3],
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let bytes = ix.to_bytes();
        let (deserialized, rest) = CompactInstruction::from_bytes(&bytes).unwrap();

        assert_eq!(rest.len(), 0);
        assert_eq!(deserialized.program_id_index, ix.program_id_index);
        assert_eq!(deserialized.accounts, ix.accounts);
        assert_eq!(deserialized.data, ix.data);
    }

    #[test]
    fn test_multiple_instructions() {
        let instructions = vec![
            CompactInstruction {
                program_id_index: 0,
                accounts: vec![1, 2],
                data: vec![1, 2, 3],
            },
            CompactInstruction {
                program_id_index: 3,
                accounts: vec![4, 5, 6],
                data: vec![7, 8, 9, 10],
            },
        ];

        let bytes = serialize_compact_instructions(&instructions);
        let parsed = parse_compact_instructions(&bytes).unwrap();

        assert_eq!(parsed.len(), instructions.len());
        for (original, parsed) in instructions.iter().zip(parsed.iter()) {
            assert_eq!(original.program_id_index, parsed.program_id_index);
            assert_eq!(original.accounts, parsed.accounts);
            assert_eq!(original.data, parsed.data);
        }
    }

    #[test]
    fn test_empty_instruction_data() {
        // Instruction with no data
        let ix = CompactInstruction {
            program_id_index: 0,
            accounts: vec![1],
            data: vec![],
        };

        let bytes = ix.to_bytes();
        let (deserialized, _) = CompactInstruction::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.data.len(), 0);
    }

    #[test]
    fn test_empty_accounts() {
        // Instruction with no accounts
        let ix = CompactInstruction {
            program_id_index: 0,
            accounts: vec![],
            data: vec![1, 2, 3],
        };

        let bytes = ix.to_bytes();
        let (deserialized, _) = CompactInstruction::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.accounts.len(), 0);
    }

    /// The flag bit halves the addressable range: 0..=127 are indices, 128..=255
    /// carry ACCOUNT_INDEX_FORWARD_SIGNER on top of an index.
    #[test]
    fn test_max_accounts() {
        let accounts: Vec<u8> = (0..=MAX_ACCOUNT_INDEX).collect();
        let ix = CompactInstruction {
            program_id_index: 0,
            accounts: accounts.clone(),
            data: vec![1],
        };

        let bytes = ix.to_bytes();
        let (deserialized, _) = CompactInstruction::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized.accounts.len(), 128);
        for (i, &byte) in deserialized.accounts.iter().enumerate() {
            assert_eq!(decode_account_index(byte), (i, false));
        }
    }

    #[test]
    fn index_byte_splits_into_index_and_forward_flag() {
        assert_eq!(decode_account_index(0), (0, false));
        assert_eq!(decode_account_index(5), (5, false));
        assert_eq!(decode_account_index(MAX_ACCOUNT_INDEX), (127, false));
        assert_eq!(decode_account_index(0x80), (0, true));
        assert_eq!(decode_account_index(0x85), (5, true));
        assert_eq!(decode_account_index(0xFF), (127, true));
    }

    /// A program-id index cannot carry the flag, so a high bit there means the
    /// client packed an index the format can no longer represent.
    #[test]
    fn program_id_index_above_the_ceiling_is_rejected() {
        let mut bytes = vec![0x80u8, 0];
        bytes.extend(&0u16.to_le_bytes());
        assert!(CompactInstruction::from_bytes(&bytes).is_err());
        assert!(CompactInstructionRef::from_bytes(&bytes).is_err());
    }

    #[test]
    fn account_flags_encode_signer_and_writable_independently() {
        assert_eq!(account_flags(false, false), 0b00);
        assert_eq!(account_flags(true, false), 0b01);
        assert_eq!(account_flags(false, true), 0b10);
        assert_eq!(account_flags(true, true), 0b11);
    }

    #[test]
    #[should_panic(expected = "account count exceeds u8 max")]
    fn test_256_accounts_panics() {
        // The *count* is still a u8, independent of the index ceiling: 256
        // entries would truncate to 0 and corrupt the stream.
        let accounts: Vec<u8> = (0..=255).collect(); // 256 elements
        let ix = CompactInstruction {
            program_id_index: 0,
            accounts,
            data: vec![1],
        };
        let _ = ix.to_bytes(); // should panic
    }

    #[test]
    fn test_large_data() {
        // Test with large instruction data (close to u16::MAX)
        let data = vec![0x42; 1000];
        let ix = CompactInstruction {
            program_id_index: 0,
            accounts: vec![1],
            data: data.clone(),
        };

        let bytes = ix.to_bytes();
        let (deserialized, _) = CompactInstruction::from_bytes(&bytes).unwrap();

        assert_eq!(deserialized.data.len(), 1000);
        assert_eq!(deserialized.data, data);
    }

    #[test]
    fn test_invalid_truncated_data() {
        // Truncated instruction data
        let bytes = vec![0, 2, 1, 2]; // program_id, num_accounts, accounts... but missing data_len

        let result = CompactInstruction::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_short_buffer() {
        // Buffer too short (less than minimum 4 bytes)
        let bytes = vec![0, 1, 2];

        let result = CompactInstruction::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_data_length_mismatch() {
        // Data length field says 10 bytes but only 5 provided
        let mut bytes = vec![0, 1, 1]; // program_id, num_accounts=1, account=1
        bytes.extend(&10u16.to_le_bytes()); // data_len = 10
        bytes.extend(&[1, 2, 3, 4, 5]); // only 5 bytes of data

        let result = CompactInstruction::from_bytes(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_instructions_list() {
        // Empty list of instructions
        let instructions: Vec<CompactInstruction> = vec![];

        let bytes = serialize_compact_instructions(&instructions);
        let parsed = parse_compact_instructions(&bytes).unwrap();

        assert_eq!(parsed.len(), 0);
    }

    #[test]
    fn test_compact_instructions_wrapper() {
        // Test CompactInstructions wrapper struct
        let compact = CompactInstructions {
            inner_instructions: vec![CompactInstruction {
                program_id_index: 0,
                accounts: vec![1, 2],
                data: vec![0xAB, 0xCD],
            }],
        };

        let bytes = compact.into_bytes();
        let parsed = parse_compact_instructions(&bytes).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].program_id_index, 0);
        assert_eq!(parsed[0].accounts, vec![1, 2]);
        assert_eq!(parsed[0].data, vec![0xAB, 0xCD]);
    }

    /// Test demonstrating Issue #11 fix concept:
    /// Same indices with different account orderings should produce different extended payloads
    #[test]
    fn test_account_ordering_affects_signature() {
        // This test verifies the conceptual fix for Issue #11
        // The actual hash computation happens in execute.rs with real AccountInfo
        // Here we demonstrate that the account indices are preserved in serialization

        let ix = CompactInstruction {
            program_id_index: 0,
            accounts: vec![1, 2], // Transfer from accounts[1] to accounts[2]
            data: vec![0x01],     // Transfer instruction
        };

        let bytes = ix.to_bytes();

        // The serialized format preserves exact indices
        // [program_id: 0] [num_accounts: 2] [acc_idx: 1] [acc_idx: 2] [data_len: 1] [data: 0x01]
        assert_eq!(bytes[0], 0); // program_id_index
        assert_eq!(bytes[1], 2); // num_accounts
        assert_eq!(bytes[2], 1); // first account index
        assert_eq!(bytes[3], 2); // second account index

        // If accounts are reordered in transaction (Issue #11 attack):
        // accounts[1] and accounts[2] would point to different pubkeys
        // causing hash(pubkey[1], pubkey[2]) != hash(pubkey[2], pubkey[1])
        // This is verified at runtime in execute.rs::compute_accounts_hash
    }
}

/// Golden-vector coverage for the accounts-hash preimage.
///
/// The vectors live in `test-vectors/accounts-hash.json` and are generated by a
/// third implementation, so neither this file nor either SDK is its own oracle.
/// `sdk/sdk-kit/tests/packing.test.ts` asserts against the same file, which is
/// what ties the wire format together across the three codebases — a stale SDK
/// build or a one-sided encoding change fails here rather than as an
/// unexplained `InvalidMessageHash` against a validator.
#[cfg(test)]
mod accounts_hash_vectors {
    use sha2::{Digest, Sha256};

    use super::*;

    const VECTORS: &str = include_str!("../../test-vectors/accounts-hash.json");

    /// The vectors address accounts by a 32-byte key whose last byte is the only
    /// non-zero one, so they can be reconstructed here without a base58 decoder.
    fn decode_base58(s: &str) -> [u8; 32] {
        const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        let mut bytes: Vec<u8> = vec![0];
        for c in s.bytes() {
            let digit = ALPHABET.iter().position(|&a| a == c).expect("base58 char") as u32;
            let mut carry = digit;
            for b in bytes.iter_mut().rev() {
                let v = (*b as u32) * 58 + carry;
                *b = (v & 0xff) as u8;
                carry = v >> 8;
            }
            while carry > 0 {
                bytes.insert(0, (carry & 0xff) as u8);
                carry >>= 8;
            }
        }
        let leading_zeros = s.bytes().take_while(|&c| c == b'1').count();
        let mut out = vec![0u8; leading_zeros];
        out.extend_from_slice(&bytes[bytes.len().saturating_sub(32 - leading_zeros)..]);
        while out.len() < 32 {
            out.insert(0, 0);
        }
        out.try_into().expect("32 bytes")
    }

    #[test]
    fn preimage_and_hash_match_the_golden_vectors() {
        let doc: serde_json::Value = serde_json::from_str(VECTORS).expect("vector file parses");
        let vectors = doc["vectors"].as_array().expect("vectors array");
        assert!(!vectors.is_empty());

        for vector in vectors {
            let name = vector["name"].as_str().unwrap();

            let accounts: Vec<([u8; 32], bool, bool)> = vector["accounts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|a| {
                    (
                        decode_base58(a["address"].as_str().unwrap()),
                        a["isSigner"].as_bool().unwrap(),
                        a["isWritable"].as_bool().unwrap(),
                    )
                })
                .collect();

            // Owned first so the borrowed `CompactInstructionRef`s below outlive
            // nothing temporary.
            let index_bytes: Vec<Vec<u8>> = vector["compactInstructions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|ix| {
                    ix["accountIndexes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|i| i.as_u64().unwrap() as u8)
                        .collect()
                })
                .collect();

            let compact: Vec<CompactInstructionRef<'_>> = vector["compactInstructions"]
                .as_array()
                .unwrap()
                .iter()
                .zip(&index_bytes)
                .map(|(ix, accounts)| CompactInstructionRef {
                    program_id_index: ix["programIdIndex"].as_u64().unwrap() as u8,
                    accounts,
                    data: &[],
                })
                .collect();

            let preimage = accounts_hash_preimage_with(&compact, |idx, out| {
                let (key, is_signer, is_writable) = accounts
                    .get(idx)
                    .copied()
                    .ok_or(ProgramError::InvalidInstructionData)?;
                out.extend_from_slice(&key);
                out.push(account_flags(is_signer, is_writable));
                Ok(())
            })
            .expect("preimage builds");

            assert_eq!(
                hex(&preimage),
                vector["preimageHex"].as_str().unwrap(),
                "{name}: preimage diverged from the golden vector"
            );
            assert_eq!(
                hex(&Sha256::digest(&preimage)),
                vector["hashHex"].as_str().unwrap(),
                "{name}: hash diverged from the golden vector"
            );
        }
    }

    /// The forward-signer bit addresses no account, so masking it must leave the
    /// digest alone — otherwise requesting forwarding would silently invalidate
    /// a signature over the same accounts.
    #[test]
    fn the_forward_flag_is_masked_out_of_the_digest() {
        let doc: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let by_name = |n: &str| -> String {
            doc["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == n)
                .unwrap_or_else(|| panic!("vector {n} present"))["hashHex"]
                .as_str()
                .unwrap()
                .to_string()
        };
        assert_eq!(
            by_name("single-transfer"),
            by_name("forward-flag-does-not-change-the-digest")
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
