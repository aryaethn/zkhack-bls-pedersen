use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};

use crate::bls::verify;
use crate::data::puzzle_data;

fn blake2s_bits(msg: &[u8]) -> Vec<Fr> {
    let d = blake2s_simd::blake2s(msg);
    let bytes = d.as_bytes();
    let mut bits = Vec::with_capacity(256);
    for i in 0..256 {
        let byte = bytes[i / 8];
        let bit = (byte >> (i % 8)) & 1;
        bits.push(if bit == 1 { Fr::one() } else { Fr::zero() });
    }
    bits
}

fn gauss_solve_256(a_cols: &[Vec<Fr>], b: &[Fr]) -> Vec<Fr> {
    let n = 256usize;
    let mut mat = vec![vec![Fr::zero(); n + 1]; n];
    for col in 0..n {
        for row in 0..n {
            mat[row][col] = a_cols[col][row];
        }
    }
    for row in 0..n {
        mat[row][n] = b[row];
    }

    let mut row = 0usize;
    for col in 0..n {
        let mut piv = row;
        while piv < n && mat[piv][col].is_zero() {
            piv += 1;
        }
        if piv == n { continue; }
        if piv != row { mat.swap(piv, row); }
        let inv = mat[row][col].inverse().expect("non-invertible pivot; matrix likely singular");
        for j in col..=n { mat[row][j] *= inv; }
        let pivot_row_vals = mat[row].clone();
        for i in 0..n {
            if i != row {
                let factor = mat[i][col];
                if !factor.is_zero() {
                    for j in col..=n { mat[i][j] -= factor * pivot_row_vals[j]; }
                }
            }
        }
        row += 1;
        if row == n { break; }
    }

    let mut x = vec![Fr::zero(); n];
    for i in 0..n { x[i] = mat[i][n]; }
    x
}

pub fn forge_and_verify_for_username(username: &[u8]) {
    let (pk, ms, sigs) = puzzle_data();
    for (m, sig) in ms.iter().zip(sigs.iter()) { verify(pk, m, *sig); }
    let a_cols: Vec<Vec<Fr>> = ms.iter().map(|m| blake2s_bits(m)).collect();
    let b_bits = blake2s_bits(username);
    let coeffs = gauss_solve_256(&a_cols, &b_bits);

    let mut acc = G1Projective::zero();
    for (coef, sig_aff) in coeffs.iter().zip(sigs.iter()) {
        if !coef.is_zero() { let term = sig_aff.into_projective().mul(coef.into_repr()); acc += term; }
    }
    let forged_sig: G1Affine = acc.into_affine();
    verify(pk, username, forged_sig);
}



