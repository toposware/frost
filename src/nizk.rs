// -*- mode: rust; -*-
//
// This file is part of ice-frost.
// Copyright (c) 2020 isis lovecruft
// Copyright (c) 2021-2022 Toposware Inc.
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Toposware developers <dev@toposware.com>

//! Zero-knowledge proofs.

use crate::keygen::Error;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use rand::CryptoRng;
use rand::Rng;

use sha2::Digest;
use sha2::Sha512;

/// A proof of knowledge of a secret key, created by making a Schnorr signature
/// with the secret key.
///
/// This proof is created by making a pseudo-Schnorr signature,
/// \\( \sigma\_i = (s\_i, r\_i) \\) using \\( a\_{i0} \\) (from
/// `ice_frost::keygen::DistributedKeyGeneration::<RoundOne>::compute_share`)
/// as the secret key, such that \\( k \stackrel{\\$}{\leftarrow} \mathbb{Z}\_q \\),
/// \\( M\_i = g^k \\), \\( s\_i = \mathcal{H}(i, \phi, g^{a\_{i0}}, M\_i) \\),
/// \\( r\_i = k + a\_{i0} \cdot s\_i \\).
///
/// Verification is done by calculating \\(M'\_i = g^r + A\_i^{-s}\\),
/// where \\(A\_i = g^{a_i}\\), and using it to compute
/// \\(s'\_i = \mathcal{H}(i, \phi, A\_i, M'\_i)\\), then finally
/// \\(s\_i \stackrel{?}{=} s'\_i\\).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NizkOfSecretKey {
    /// The scalar portion of the Schnorr signature encoding the context.
    s: Scalar,
    /// The scalar portion of the Schnorr signature which is the actual signature.
    r: Scalar,
}

impl NizkOfSecretKey {
    /// Prove knowledge of a secret key.
    pub fn prove(
        index: &u32,
        secret_key: &Scalar,
        public_key: &RistrettoPoint,
        context_string: &str,
        mut csprng: impl Rng + CryptoRng,
    ) -> Self
    {
        let k: Scalar = Scalar::random(&mut csprng);
        let M: RistrettoPoint = &k * &RISTRETTO_BASEPOINT_TABLE;

        let mut hram = Sha512::new();

        hram.update(index.to_be_bytes());
        hram.update(context_string);
        hram.update(public_key.compress().as_bytes());
        hram.update(M.compress().as_bytes());

        let s = Scalar::from_hash(hram);
        let r = k + (secret_key * s);

        NizkOfSecretKey { s, r }
    }

    /// Verify that the prover does indeed know the secret key.
    pub fn verify(&self, index: &u32, public_key: &RistrettoPoint, context_string: &str) -> Result<(), Error> {
        let M_prime: RistrettoPoint = (&RISTRETTO_BASEPOINT_TABLE * &self.r) + (public_key * -&self.s);

        let mut hram = Sha512::new();

        hram.update(index.to_be_bytes());
        hram.update(context_string);
        hram.update(public_key.compress().as_bytes());
        hram.update(M_prime.compress().as_bytes());

        let s_prime = Scalar::from_hash(hram);

        if self.s == s_prime {
            return Ok(());
        }

        Err(Error::InvalidProofOfKnowledge)
    }

    /// Serialise this proof to an array of bytes
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut res = [0u8; 64];
        res[0..32].copy_from_slice(&self.s.to_bytes());
        res[32..64].copy_from_slice(&self.r.to_bytes());

        res
    }

    /// Deserialise this slice of bytes to a NiZK proof
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<NizkOfSecretKey, Error> {
        let s = Scalar::from_canonical_bytes(
            bytes[0..32]
                .try_into()
                .map_err(|_| Error::SerialisationError)?
        ).ok_or(Error::SerialisationError)?;

        let r = Scalar::from_canonical_bytes(
            bytes[32..64]
                .try_into()
                .map_err(|_| Error::SerialisationError)?
        ).ok_or(Error::SerialisationError)?;

        Ok(NizkOfSecretKey { s, r })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn test_serialization() {
        let mut rng = OsRng;

        for _ in 0..100 {
            let nizk = NizkOfSecretKey {
                s: Scalar::random(&mut rng),
                r: Scalar::random(&mut rng),
            };
            let bytes = nizk.to_bytes();
            assert_eq!(nizk, NizkOfSecretKey::from_bytes(&bytes).unwrap());
        }
    }
}
