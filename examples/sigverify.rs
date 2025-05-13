use fd_ed25519::{fd_ed25519_verify, fd_sha512_init, fd_sha512_t};
use rand::Rng;
use solana_sdk::{
    hash::Hash,
    signature::{Keypair, Signer as SolanaSigner, SIGNATURE_BYTES},
    transaction::VersionedTransaction,
};

pub fn verify_with_fd_ed25519(txn: &VersionedTransaction, message_bytes: &[u8]) -> bool {
    let maybe_sha_ctx = std::mem::MaybeUninit::<fd_sha512_t>::uninit();
    let mut sha_ctx = unsafe { maybe_sha_ctx.assume_init() }; // initialized in loop
    txn.signatures
        .iter()
        .zip(txn.message.static_account_keys())
        .all(|(signature, pubkey)| {
            fd_sha512_init(&mut sha_ctx);
            let result_code = fd_ed25519_verify(
                message_bytes,
                unsafe { &*(signature.as_ref().as_ptr() as *const [u8; SIGNATURE_BYTES]) },
                pubkey.as_array(),
                &mut sha_ctx,
            );
            result_code.is_ok()
        })
}

fn main() {
    let mut rng = rand::thread_rng();
    for i in 0..1_000 {
        let recent_blockhash = Hash::new_unique();
        let kp = Keypair::new();
        let txn = VersionedTransaction::from(solana_sdk::system_transaction::transfer(
            &kp,
            &kp.pubkey(),
            1,
            recent_blockhash,
        ));

        let mut txn_bytes = txn.message.serialize();
        assert_eq!(
            txn.verify_with_results().into_iter().all(|r| r),
            verify_with_fd_ed25519(&txn, &txn_bytes),
            "Mismatch between Solana and FireDancer at index {i}"
        );

        let rand_idx = rng.gen_range(0..txn_bytes.len());
        txn_bytes[rand_idx] ^= 1; // flip bits
        assert!(
            !verify_with_fd_ed25519(&txn, &txn_bytes),
            "Corrupted transaction should fail sigverify"
        );
    }
}
