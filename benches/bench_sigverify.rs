use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fd_ed25519::{fd_ed25519_verify, fd_sha512_init, fd_sha512_t};
use solana_sdk::{
    hash::Hash,
    signature::{Keypair, Signer, SIGNATURE_BYTES},
    transaction::VersionedTransaction,
};

pub fn verify_with_fd_ed25519(txn: &VersionedTransaction, message_bytes: &[u8]) -> bool {
    let maybe_sha_ctx = std::mem::MaybeUninit::<fd_sha512_t>::uninit();
    // no need to init, already done here:
    // https://github.com/firedancer-io/firedancer/blob/91c4a47971fc26c3e01025a1a9972d6320a2961a/src/ballet/ed25519/fd_ed25519_user.c#L205
    let mut sha_ctx = unsafe { maybe_sha_ctx.assume_init() };
    txn.signatures
        .iter()
        .zip(txn.message.static_account_keys())
        .all(|(signature, pubkey)| {
            let result_code = fd_ed25519_verify(
                message_bytes,
                unsafe { &*(signature.as_ref().as_ptr() as *const [u8; SIGNATURE_BYTES]) },
                pubkey.as_array(),
                &mut sha_ctx,
            );
            result_code.is_ok()
        })
}

fn make_signed_txn() -> (VersionedTransaction, Vec<u8>) {
    let recent_blockhash = Hash::new_unique();
    let kp = Keypair::new();
    let txn = VersionedTransaction::from(solana_sdk::system_transaction::transfer(
        &kp,
        &kp.pubkey(),
        1,
        recent_blockhash,
    ));

    let txn_bytes = bincode::serialize(&txn).unwrap();
    (txn, txn_bytes)
}

fn bench_solana_sigverify(c: &mut Criterion) {
    let (txn, _txn_bytes) = make_signed_txn();

    c.bench_function("solana_sigverify", |b| {
        b.iter(|| {
            // Prevent LLVM from optimising the call away
            VersionedTransaction::verify_with_results(black_box(&txn));
        });
    });
}

fn bench_fd_sigverify(c: &mut Criterion) {
    let (txn, txn_bytes) = make_signed_txn();

    c.bench_function("fd_sigverify", |b| {
        b.iter(|| {
            verify_with_fd_ed25519(black_box(&txn), black_box(&txn_bytes));
        });
    });
}

criterion_group!(benches, bench_solana_sigverify, bench_fd_sigverify);
criterion_main!(benches);
