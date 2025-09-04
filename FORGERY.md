## BLS + Pedersen Forgery (High-Level)

This challenge relies on two linear structures:

- **Pedersen hash linearity**: With fixed generators `G[0..255]`, the hash of a 256-bit Blake2s digest `b` is
  \( H(b) = \sum_{i=0}^{255} b[i] \cdot G[i] \) over the curve group. Bits are treated as field elements 0/1.
- **BLS signature linearity**: A BLS signature is \(\sigma = sk \cdot H(m)\). Scalar/point linear combinations commute with multiplication by the secret key \(sk\).

Given 256 leaked messages `m_i` and signatures `σ_i = sk · H(m_i)`, form a 256×256 matrix `B` whose `i`-th column is the 256-bit Blake2s of `m_i` as field elements. For a target message `m*` with digest bits `b*`, solve the linear system over the scalar field:

\[ B · c = b* \]

This yields coefficients `c[0..255]` such that:

\[ \sum_i c[i] · H(m_i) = H(m*) \]

By linearity of BLS:

\[ \sum_i c[i] · σ_i = \sum_i c[i] · (sk · H(m_i)) = sk · H(m*) \]

Hence \( \sigma^* = \sum_i c[i] · σ_i \) is a valid signature on `m*` without knowing `sk`.

### Practical Steps
1. Compute Blake2s for each leaked `m_i` and build `B` (256 columns of 256 bits).
2. Compute Blake2s for target message `m*` to get `b*`.
3. Solve \( B · c = b* \) via Gaussian elimination over the BLS12-381 scalar field.
4. Combine leaked signatures: \( \sigma^* = \sum_i c[i] · σ_i \).
5. Verify with the given public key: `verify(pk, m*, σ*)`.

### Notes
- The attack works because the Pedersen setup is fixed and exposes a vector-space structure for Blake2s bits, and BLS preserves linear combinations in the group.
- If `B` is full-rank (invertible), a solution exists for any `b*` (and thus any target message).


