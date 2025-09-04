use bls_pedersen::bls::verify;
use bls_pedersen::data::puzzle_data;
use bls_pedersen::PUZZLE_DESCRIPTION;
use prompt::{puzzle, welcome};
use bls_pedersen::forge::forge_and_verify_for_username;

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);
    let (pk, ms, sigs) = puzzle_data();
    for (m, sig) in ms.iter().zip(sigs.iter()) {
        verify(pk, m, *sig);
    }

    forge_and_verify_for_username(b"Aryaethn");
}
