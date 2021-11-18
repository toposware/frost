// -*- mode: rust; -*-
//
// This file is part of ice-frost.
// Copyright (c) 2020 isis lovecruft
// Copyright (c) 2021 Toposware Inc.
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Toposware developers <dev@toposware.com>

//! A variation of Pedersen's distributed key generation (DKG) protocol.
//!
//! This implementation uses the [typestate] design pattern (also called session
//! types) behind the scenes to enforce that more programming errors are discoverable
//! at compile-time.  Additionally, secrets generated for commitment openings, secret keys,
//! nonces in zero-knowledge proofs, etc., are zeroed-out in memory when they are dropped
//! out of scope.
//!
//! # Details
//!
//! ## Round One
//!
//! * Step #1: Every participant \\(P\_i\\) samples \\(t\\) random values \\((a\_{i0}, \\dots, a\_{i(t-1)})\\)
//!            uniformly in \\(\mathbb{Z}\_q\\), and uses these values as coefficients to define a
//!            polynomial \\(f\_i\(x\) = \sum\_{j=0}^{t-1} a\_{ij} x^{j}\\) of degree \\( t-1 \\) over
//!            \\(\mathbb{Z}\_q\\).
//!
//! (Yes, I know the steps are out-of-order. These are the step numbers as given in the paper.  I do them
//! out-of-order because it saves one scalar multiplication.)
//!
//! * Step #3: Every participant \\(P\_i\\) computes a public commitment
//!            \\(C\_i = \[\phi\_{i0}, \\dots, \phi\_{i(t-1)}\]\\), where \\(\phi\_{ij} = g^{a\_{ij}}\\),
//!            \\(0 \le j \le t-1\\).
//!
//! * Step #2: Every \\(P\_i\\) computes a proof of knowledge to the corresponding secret key
//!            \\(a\_{i0}\\) by calculating a pseudo-Schnorr signature \\(\sigma\_i = \(s, r\)\\).  (In
//!            the FROST paper: \\(\sigma\_i = \(\mu\_i, c\_i\)\\), but we stick with Schnorr's
//!            original notation here.)
//!
//! * Step #4: Every participant \\(P\_i\\) broadcasts \\(\(C\_i\\), \\(\sigma\_i\)\\) to all other participants.
//!
//! * Step #5: Upon receiving \\((C\_l, \sigma\_l)\\) from participants \\(1 \le l \le n\\), \\(l \ne i\\),
//!            participant \\(P\_i\\) verifies \\(\sigma\_l = (s\_l, r\_l)\\), by checking:
//!            \\(s\_l \stackrel{?}{=} \mathcal{H}(l, \Phi, \phi\_{l0}, g^{r\_l} \cdot \phi\_{l0}^{-s\_i})\\).
//!            If any participants' proofs cannot be verified, return their participant indices.
//!
//! ## Round Two
//!
//! * Step #1: Each \\(P\_i\\) securely sends to each other participant \\(P\_l\\) a secret share
//!            \\((l, f\_i(l))\\) using their secret polynomial \\(f\_i(l)\\) and keeps \\((i, f\_i(i))\\)
//!            for themselves.
//!
//! * Step #2: Each \\(P\_i\\) verifies their shares by calculating:
//!            \\(g^{f\_l(i)} \stackrel{?}{=} \prod\_{k=0}^{n-1} \\)\\(\phi\_{lk}^{i^{k} \mod q}\\),
//!            aborting if the check fails.
//!
//! * Step #3: Each \\(P\_i\\) calculates their secret signing key as the product of all the secret
//!            polynomial evaluations (including their own):
//!            \\(a\_i = g^{f\_i(i)} \cdot \prod\_{l=0}^{n-1} g^{f\_l(i)}\\), as well as calculating
//!            the group public key in similar fashion from the commitments from round one:
//!            \\(A = C\_i \cdot \prod\_{l=0}^{n-1} C_l\\).
//!
//! # Examples
//!
//! ```rust
//! use ice_frost::DistributedKeyGeneration;
//! use ice_frost::Parameters;
//! use ice_frost::Participant;
//! use curve25519_dalek::ristretto::RistrettoPoint;
//! use curve25519_dalek::traits::Identity;
//! use curve25519_dalek::scalar::Scalar;
//!
//! # fn do_test() -> Result<(), ()> {
//! // Set up key shares for a threshold signature scheme which needs at least
//! // 2-out-of-3 signers.
//! let params = Parameters { t: 2, n: 3 };
//!
//! // Alice, Bob, and Carol each generate their secret polynomial coefficients
//! // and commitments to them, as well as a zero-knowledge proof of a secret key.
//! let (alice, alice_coeffs, alice_dh_sk) = Participant::new(&params, 1, "Φ");
//! let (bob, bob_coeffs, bob_dh_sk) = Participant::new(&params, 2, "Φ");
//! let (carol, carol_coeffs, carol_dh_sk) = Participant::new(&params, 3, "Φ");
//!
//! // They send these values to each of the other participants (out of scope
//! // for this library), or otherwise publish them somewhere.
//! //
//! // alice.send_to(bob);
//! // alice.send_to(carol);
//! // bob.send_to(alice);
//! // bob.send_to(carol);
//! // carol.send_to(alice);
//! // carol.send_to(bob);
//! //
//! // NOTE: They should only send the `alice`, `bob`, and `carol` structs, *not*
//! //       the `alice_coefficients`, etc.
//! //
//! // Bob and Carol verify Alice's zero-knowledge proof by doing:
//!
//! alice.proof_of_secret_key.verify(&alice.index, &alice.public_key().unwrap(), "Φ").or(Err(()))?;
//!
//! // Similarly, Alice and Carol verify Bob's proof:
//! bob.proof_of_secret_key.verify(&bob.index, &bob.public_key().unwrap(), "Φ").or(Err(()))?;
//!
//! // And, again, Alice and Bob verify Carol's proof:
//! carol.proof_of_secret_key.verify(&carol.index, &carol.public_key().unwrap(), "Φ").or(Err(()))?;
//!
//! // Alice enters round one of the distributed key generation protocol.
//! let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice_dh_sk, &alice.index, &alice_coeffs,
//!                                                      &mut alice_other_participants, "Φ").or(Err(()))?;
//!
//! // Alice then collects the secret shares which they send to the other participants:
//! let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! // send_to_bob(alice_their_encrypted_secret_shares[0]);
//! // send_to_carol(alice_their_encrypted_secret_shares[1]);
//!
//! // Bob enters round one of the distributed key generation protocol.
//! let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob_dh_sk, &bob.index, &bob_coeffs,
//!                                                    &mut bob_other_participants, "Φ").or(Err(()))?;
//!
//! // Bob then collects the secret shares which they send to the other participants:
//! let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! // send_to_alice(bob_their_encrypted_secret_shares[0]);
//! // send_to_carol(bob_their_encrypted_secret_shares[1]);
//!
//! // Carol enters round one of the distributed key generation protocol.
//! let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol_dh_sk, &carol.index, &carol_coeffs,
//!                                                      &mut carol_other_participants, "Φ").or(Err(()))?;
//!
//! // Carol then collects the secret shares which they send to the other participants:
//! let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares()?;
//! // send_to_alice(carol_their_encrypted_secret_shares[0]);
//! // send_to_bob(carol_their_encrypted_secret_shares[1]);
//!
//! // Each participant now has a vector of secret shares given to them by the other participants:
//! let alice_my_encrypted_secret_shares = vec!(bob_their_encrypted_secret_shares[0].clone(),
//!                                   carol_their_encrypted_secret_shares[0].clone());
//! let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//!                                 carol_their_encrypted_secret_shares[1].clone());
//! let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//!                                   bob_their_encrypted_secret_shares[1].clone());
//!
//! // The participants then use these secret shares from the other participants to advance to
//! // round two of the distributed key generation protocol.
//! let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares).or(Err(()))?;
//! let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares).or(Err(()))?;
//! let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares).or(Err(()))?;
//!
//! // Each participant can now derive their long-lived secret keys and the group's
//! // public key.
//! let (alice_group_key, alice_secret_key) = alice_state.finish(alice.commitments).or(Err(()))?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish(bob.commitments).or(Err(()))?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish(carol.commitments).or(Err(()))?;
//!
//! // They should all derive the same group public key.
//! assert!(alice_group_key == bob_group_key);
//! assert!(carol_group_key == bob_group_key);
//!
//! // Alice, Bob, and Carol can now create partial threshold signatures over an agreed upon
//! // message with their respective secret keys, which they can then give to a
//! // [`SignatureAggregator`] to create a 2-out-of-3 threshold signature.
//! # Ok(())}
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! [typestate]: http://cliffle.com/blog/rust-typestate/

#[cfg(feature = "std")]
use std::boxed::Box;
#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

#[cfg(feature = "alloc")]
use alloc::string::{String, ToString};
#[cfg(feature = "std")]
use std::string::{String, ToString};

use core::convert::TryInto;
use core::fmt;
use core::cmp::Ordering;
use core::ops::Deref;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand::rngs::OsRng;
use rand::RngCore;

use sha2::Digest;
use sha2::Sha512;

use hkdf::Hkdf;

use zeroize::Zeroize;

use crate::nizk::NizkOfSecretKey;
use crate::parameters::Parameters;
use crate::signature::calculate_lagrange_coefficients;

use aes::{Aes256, Aes256Ctr};
use aes::cipher::{
    FromBlockCipher, NewBlockCipher,
    generic_array::GenericArray,
    StreamCipher,
};

/// Errors that may happen during Key Generation
#[derive(Debug, PartialEq)]
pub enum Error {
    /// Serialisation error
    SerialisationError,
    /// Encrypted secret share decryption failure
    DecryptionError,
    /// Secret share verification failure
    ShareVerificationError,
    /// Complaint verification failure
    ComplaintVerificationError,
    /// GroupKey generation failure
    InvalidGroupKey,
    /// The participant is missing some others' secret shares
    MissingShares,
    /// At least one complaint has been issued during to_round_two() execution
    Complaint(Vec::<Complaint>),
    /// Custom error
    Custom(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::SerialisationError => {
                write!(f, "An error happened while deserialising.")
            },
            Error::DecryptionError => {
                write!(f, "Could not decrypt encrypted share.")
            },
            Error::ShareVerificationError => {
                write!(f, "The secret share is not correct.")
            },
            Error::ComplaintVerificationError => {
                write!(f, "The complaint is not correct.")
            },
            Error::InvalidGroupKey => {
                write!(f, "Could not generate a valid group key with the given commitments.")
            },
            Error::MissingShares => {
                write!(f, "Some shares are missing.")
            },
            Error::Complaint(complaints) => {
                write!(f, "{:?}", complaints)
            },
            Error::Custom(string) => {
                write!(f, "{:?}", string)
            },
        }
    }
}

/// A struct for holding a shard of the shared secret, in order to ensure that
/// the shard is overwritten with zeroes when it falls out of scope.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Coefficients(pub(crate) Vec<Scalar>);

impl Coefficients {
    /// Serialise these coefficients as a Vec of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::with_capacity(self.0.len() * 32 + 4);
        let mut tmp = self
            .0
            .iter()
            .map(|e| e.to_bytes())
            .collect::<Vec<[u8; 32]>>();
        res.extend_from_slice(&mut TryInto::<u32>::try_into(tmp.len()).unwrap().to_le_bytes());
        for elem in tmp.iter_mut() {
            res.extend_from_slice(elem);
        }

        res
    }

    /// Deserialise this slice of bytes to a `Coefficients`
    pub fn from_bytes(bytes: &[u8]) -> Result<Coefficients, Error> {
        let len = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );
        let mut points: Vec<Scalar> =
            Vec::with_capacity(len as usize);
        let mut index_slice = 4usize;
        let mut array = [0u8; 32];

        for _ in 0..len {
            array.copy_from_slice(&bytes[index_slice..index_slice + 32]);
            points.push(
                Scalar::from_canonical_bytes(array)
                    .ok_or(Error::SerialisationError)?,
            );
            index_slice += 32;
        }

        Ok(Coefficients(points))
    }
}

/// A commitment to a participant's secret polynomial coefficients for Feldman's
/// verifiable secret sharing scheme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiableSecretSharingCommitment {
    /// The index of this participant.
    pub index: u32,
    /// The commitments to the participant's secret coefficients.
    pub points: Vec<RistrettoPoint>,
}

impl VerifiableSecretSharingCommitment {
    /// Retrieve \\( \alpha_{i0} * B \\), where \\( B \\) is the Ristretto basepoint.
    pub fn public_key(&self) -> Option<&RistrettoPoint> {
        if !self.points.is_empty() {
            return Some(&self.points[0]);
        }
        None
    }

    /// Evaluate g^P(i) without knowing the secret coefficients of the polynomial
    pub fn evaluate_hiding(&self, term: &Scalar) -> RistrettoPoint {
        let mut sum = RistrettoPoint::identity();

        // Evaluate using Horner's method.
        for (k, coefficient) in self.points.iter().rev().enumerate() {
            // The secret is the constant term in the polynomial
            sum += coefficient;

            if k != (self.points.len() - 1) {
                sum *= term;
            }
        }

        sum
        
    }

    /// Serialise this commitment to the secret polynomial coefficients as a Vec of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::with_capacity(self.points.len() * 32 + 8);
        res.extend_from_slice(&self.index.to_le_bytes());
        let mut tmp = self
            .points
            .iter()
            .map(|e| e.compress().to_bytes())
            .collect::<Vec<[u8; 32]>>();
        res.extend_from_slice(&mut TryInto::<u32>::try_into(tmp.len()).unwrap().to_le_bytes());
        for elem in tmp.iter_mut() {
            res.extend_from_slice(elem);
        }

        res
    }

    /// Deserialise this slice of bytes to a `VerifiableSecretSharingCommitment`
    pub fn from_bytes(bytes: &[u8]) -> Result<VerifiableSecretSharingCommitment, Error> {
        let index = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );
        let len = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );
        let mut points: Vec<RistrettoPoint> =
            Vec::with_capacity(len as usize);
        let mut index_slice = 8usize;
        let mut array = [0u8; 32];

        for _ in 0..len {
            array.copy_from_slice(&bytes[index_slice..index_slice + 32]);
            points.push(
                CompressedRistretto(array)
                    .decompress()
                    .ok_or(Error::SerialisationError)?,
            );
            index_slice += 32;
        }

        Ok(VerifiableSecretSharingCommitment { index, points })
    }
}

/// A Diffie-Hellman private key wrapper type around a Scalar
#[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct DHPrivateKey(pub(crate) Scalar);

impl DHPrivateKey {
    /// Serialise this Diffie-Hellman private key as an array of bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Deserialise this slice of bytes to a `DHPrivateKey`
    pub fn from_bytes(bytes: &[u8]) -> Result<DHPrivateKey, Error> {
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[..32]);

        let scalar = Scalar::from_canonical_bytes(array)
            .ok_or(Error::SerialisationError)?;

        Ok(DHPrivateKey(scalar))
    }
}

impl Deref for DHPrivateKey {
    type Target = Scalar;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A Diffie-Hellman public key wrapper type around a RistrettoPoint
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DHPublicKey(pub(crate) RistrettoPoint);

impl DHPublicKey {
    /// Serialise this Diffie-Hellman public key as an array of bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Deserialise this slice of bytes to a `DHPublicKey`
    pub fn from_bytes(bytes: &[u8]) -> Result<DHPublicKey, Error> {
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[..32]);
        let key = CompressedRistretto(array)
            .decompress()
            .ok_or(Error::SerialisationError)?;

        Ok(DHPublicKey(key))
    }
}

impl Deref for DHPublicKey {
    type Target = RistrettoPoint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A participant in a threshold signing.
#[derive(Clone, Debug)]
pub struct Participant {
    /// The index of this participant, to keep the participants in order.
    pub index: u32,
    /// The public key used to derive symmetric keys for encrypting and 
    /// decrypting shares via DH.
    pub dh_public_key: DHPublicKey,
    /// A vector of Pedersen commitments to the coefficients of this
    /// participant's private polynomial.
    pub commitments: Option<VerifiableSecretSharingCommitment>,
    /// The zero-knowledge proof of knowledge of the secret key (a.k.a. the
    /// first coefficient in the private polynomial).  It is constructed as a
    /// Schnorr signature using \\( a_{i0} \\) as the signing key.
    pub proof_of_secret_key: Option<NizkOfSecretKey>,
    /// The zero-knowledge proof of knowledge of the DH private key.
    /// It is computed similarly to the proof_of_secret_key.
    pub proof_of_dh_private_key: NizkOfSecretKey,
}

impl Participant {
    /// Construct a new dealer for the distributed key generation protocol.
    /// A dealer generates shares for the signers. In case of resharing/refreshing,
    /// the constant coefficient is passed as input.
    ///
    /// # Inputs
    ///
    /// * The protocol instance [`Parameters`]
    /// * This dealer's `index`,
    /// * This dealer's previous `secret_key` (optional), and
    /// * A context string to prevent replay attacks.
    ///
    /// # Usage
    ///
    /// After a new participant is constructed, the `participant.index`,
    /// `participant.commitments`, and `participant.proof_of_secret_key` should
    /// be sent to every other participant in the protocol.
    ///
    /// # Returns
    ///
    /// A distributed key generation protocol [`Participant`] and that
    /// dealer's secret polynomial `Coefficients` which must be kept
    /// private, along the dealer's Diffie-Hellman secret key for secret shares encryption.
    pub fn new_dealer(parameters: &Parameters, index: u32, secret_key: Option<Scalar>, context_string: &str) -> (Self, Coefficients, DHPrivateKey) {
        // Step 1: Every participant P_i samples t random values (a_{i0}, ..., a_{i(t-1)})
        //         uniformly in ZZ_q, and uses these values as coefficients to define a
        //         polynomial f_i(x) = \sum_{j=0}^{t-1} a_{ij} x^{j} of degree t-1 over
        //         ZZ_q.
        let t: usize = parameters.t as usize;
        let mut rng: OsRng = OsRng;
        let mut coefficients: Vec<Scalar> = Vec::with_capacity(t);
        let mut commitments = VerifiableSecretSharingCommitment { index, points: Vec::with_capacity(t) };

        for _ in 0..t {
            coefficients.push(Scalar::random(&mut rng));
        }

        let coefficients = Coefficients(coefficients);

        // RICE-FROST: Every participant samples a random pair of keys (dh_private_key, dh_public_key)
        // and generates a proof of knowledge of dh_private_key. This will be used for secret shares
        // encryption and for complaint generation.

        let dh_private_key = DHPrivateKey(Scalar::random(&mut rng));
        let dh_public_key = DHPublicKey(&RISTRETTO_BASEPOINT_TABLE * &dh_private_key);

        // Compute a proof of knowledge of dh_secret_key
        let proof_of_dh_private_key: NizkOfSecretKey = NizkOfSecretKey::prove(&index, &dh_private_key, &dh_public_key, &context_string, rng);

        // Step 3: Every participant P_i computes a public commitment
        //         C_i = [\phi_{i0}, ..., \phi_{i(t-1)}], where \phi_{ij} = g^{a_{ij}},
        //         0 ≤ j ≤ t-1.
        for j in 0..t {
            commitments.points.push(&coefficients.0[j] * &RISTRETTO_BASEPOINT_TABLE);
        }

        // Yes, I know the steps are out of order.  It saves one scalar multiplication.

        // Step 2: Every P_i computes a proof of knowledge to the corresponding secret
        //         a_{i0} by calculating a Schnorr signature \alpha_i = (s, R).  (In
        //         the FROST paper: \alpha_i = (\mu_i, c_i), but we stick with Schnorr's
        //         original notation here.)
        let proof_of_secret_key: NizkOfSecretKey = NizkOfSecretKey::prove(&index, &coefficients.0[0], &commitments.points[0], &context_string, rng);

        // Step 4: Every participant P_i broadcasts C_i, \alpha_i to all other participants.
        (Participant { index, dh_public_key, commitments: Some(commitments), proof_of_secret_key: Some(proof_of_secret_key), proof_of_dh_private_key }, coefficients, dh_private_key)
    }


    /// Construct a new signer for the distributed key generation protocol.
    /// A signer combines shares from the dealers and computes a private
    /// signing key.
    ///
    /// # Inputs
    ///
    /// * The protocol instance [`Parameters`]
    /// * This signer's `index`, and
    /// * A context string to prevent replay attacks.
    ///
    /// # Usage
    ///
    /// After a new signer is constructed, the `participant.index` and
    /// `participant.proof_of_secret_key` should be sent to every
    /// other participant in the protocol. A signer has no secret
    /// coefficients, and thus no commitment to share.
    ///
    /// # Returns
    ///
    /// A distributed key generation protocol [`Participant`] and that
    /// signer's Diffie-Hellman secret key for secret shares encryption.
    pub fn new_signer(parameters: &Parameters, index: u32, context_string: &str) -> (Self, DHPrivateKey) {
        let t: usize = parameters.t as usize;
        let mut rng: OsRng = OsRng;

        // RICE-FROST: Every participant samples a random pair of keys (dh_private_key, dh_public_key)
        // and generates a proof of knowledge of dh_private_key. This will be used for secret shares
        // encryption and for complaint generation.

        let dh_private_key = DHPrivateKey(Scalar::random(&mut rng));
        let dh_public_key = DHPublicKey(&RISTRETTO_BASEPOINT_TABLE * &dh_private_key);

        // Compute a proof of knowledge of dh_secret_key
        let proof_of_dh_private_key: NizkOfSecretKey = NizkOfSecretKey::prove(&index, &dh_private_key, &dh_public_key, &context_string, rng);

        // Every signer P_j broadcasts C_j, \alpha_j to all other participants.
        (Participant { index, dh_public_key, commitments: None, proof_of_secret_key: None, proof_of_dh_private_key }, dh_private_key)
    }

    /// Retrieve \\( \alpha_{i0} * B \\), where \\( B \\) is the Ristretto basepoint.
    ///
    /// This is used to pass into the final call to `DistributedKeyGeneration::<RoundTwo>.finish()`.
    pub fn public_key(&self) -> Option<&RistrettoPoint> {
        if self.commitments.is_some() {
            return self.commitments.as_ref().unwrap().public_key();
        }

        None
    }

    /// PLACEHOLDER, MUST BE CHANGED
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::with_capacity(168);
        res
    }
    /*
    /// Serialise this participant to a Vec of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::with_capacity(168 + self.commitments.points.len() * 32); // 4 + 32 + 4 + len * 32 + 64 + 64
        res.extend_from_slice(&mut self.index.to_le_bytes());
        res.extend_from_slice(&mut self.dh_public_key.to_bytes());
        res.extend_from_slice(&mut self.commitments.to_bytes());
        res.extend_from_slice(&mut self.proof_of_secret_key.to_bytes());
        res.extend_from_slice(&mut self.proof_of_dh_private_key.to_bytes());

        res
    }
    */

    /// Deserialise this slice of bytes to a `Participant`
    pub fn from_bytes(bytes: &[u8]) -> Result<Participant, Error> {
        let index = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[4..36]);

        let dh_public_key = DHPublicKey::from_bytes(&array)?;
        let mut index_slice = 36 as usize;
        let commitments = VerifiableSecretSharingCommitment::from_bytes(&bytes[index_slice..])?;
        index_slice += 8 + commitments.points.len() * 32;

        let proof_of_secret_key =
            NizkOfSecretKey::from_bytes(&bytes[index_slice..index_slice + 64])?;
        let proof_of_dh_private_key =
            NizkOfSecretKey::from_bytes(&bytes[index_slice + 64..index_slice + 128])?;

        Ok(Participant {
            index,
            dh_public_key,
            commitments: Some(commitments),
            proof_of_secret_key: Some(proof_of_secret_key),
            proof_of_dh_private_key,
        })
    }
}

impl PartialOrd for Participant {
    fn partial_cmp(&self, other: &Participant) -> Option<Ordering> {
        match self.index.cmp(&other.index) {
            Ordering::Less => Some(Ordering::Less),
            Ordering::Equal => None, // Participants cannot have the same index.
            Ordering::Greater => Some(Ordering::Greater),
        }
    }
}

impl PartialEq for Participant {
    fn eq(&self, other: &Participant) -> bool {
        self.index == other.index
    }
}

/// Module to implement trait sealing so that `DkgState` cannot be
/// implemented for externally declared types.
mod private {
    pub trait Sealed {}

    impl Sealed for super::RoundOne {}
    impl Sealed for super::RoundTwo {}
}

/// State machine structures for holding intermediate values during a
/// distributed key generation protocol run, to prevent misuse.
#[derive(Clone, Debug)]
pub struct DistributedKeyGeneration<S: DkgState> {
    state: Box<ActualState>,
    data: S,
}

/// Shared state which occurs across all rounds of a threshold signing protocol run.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ActualState {
    /// The parameters for this instantiation of a threshold signature.
    parameters: Parameters,
    /// The index of the participant.
    index: u32,
    /// The DH private key for deriving a symmetric key to encrypt and decrypt
    /// secret shares.
    dh_private_key: DHPrivateKey,
    /// The DH public key for deriving a symmetric key to encrypt and decrypt
    /// secret shares.
    dh_public_key: DHPublicKey,
    /// A vector of tuples containing the index of each participant and that
    /// respective participant's commitments to their private polynomial
    /// coefficients.
    their_commitments: Option<Vec<VerifiableSecretSharingCommitment>>,
    /// A vector of ECPoints containing the index of each participant and that
    /// respective participant's DH public key.
    their_dh_public_keys: Vec<(u32, DHPublicKey)>,
    /// The encrypted secret shares this participant has calculated for all the other participants.
    their_encrypted_secret_shares: Option<Vec<EncryptedSecretShare>>,
    /// The secret shares this participant has received from all the other participants.
    my_secret_shares: Option<Vec<SecretShare>>,
}

impl ActualState {
    /* MUST IMPLEMENT SERIALISATION METHODS
    /// Serialise this state to a Vec of bytes
    fn to_bytes(&self) -> Vec<u8> {
        let mut res: Vec<u8> = Vec::new();
        res.extend_from_slice(&mut self.parameters.to_bytes());
        res.extend_from_slice(&mut self.dh_private_key.to_bytes());
        res.extend_from_slice(&mut self.dh_public_key.to_bytes());
        let mut tmp = self
            .their_commitments
            .unwrap()
            .iter()
            .map(|e| (e.0.to_le_bytes(), e.1.to_bytes()))
            .collect::<Vec<([u8; 4], Vec<u8>)>>();
        res.extend_from_slice(&mut TryInto::<u32>::try_into(tmp.len()).unwrap().to_le_bytes());
        for (index, commitments) in tmp.iter_mut() {
            res.extend_from_slice(index);
            res.extend_from_slice(commitments);
        }
        let mut tmp = self
            .their_dh_public_keys
            .iter()
            .map(|e| (e.0.to_le_bytes(), e.1.to_bytes()))
            .collect::<Vec<([u8; 4], [u8; 32])>>();
        res.extend_from_slice(&mut TryInto::<u32>::try_into(tmp.len()).unwrap().to_le_bytes());
        for (index, keys) in tmp.iter_mut() {
            res.extend_from_slice(index);
            res.extend_from_slice(keys);
        }
        match &self.their_encrypted_secret_shares {
            Some(v) => {
                res.push(1u8);
                let mut tmp = v.iter()
                    .map(|e| e.to_bytes())
                    .collect::<Vec<[u8; 56]>>();
                res.extend_from_slice(&mut TryInto::<u32>::try_into(tmp.len()).unwrap().to_le_bytes());
                for elem in tmp.iter_mut() {
                    res.extend_from_slice(elem);
                }
            },
            None => res.push(0u8),
        };
        match &self.my_secret_shares {
            Some(v) => {
                res.push(1u8);
                let mut tmp = v.iter()
                    .map(|e| e.to_bytes())
                    .collect::<Vec<[u8; 40]>>();
                res.extend_from_slice(&mut TryInto::<u32>::try_into(tmp.len()).unwrap().to_le_bytes());
                for elem in tmp.iter_mut() {
                    res.extend_from_slice(elem);
                }
            },
            None => res.push(0u8),
        };
    
        res
    }
    
    /// Deserialise this slice of bytes to an `ActualState`
    fn from_bytes(bytes: &[u8]) -> Result<ActualState, Error> {
        let mut array = [0u8; 8];
        array.copy_from_slice(&bytes[..8]);
        let parameters = Parameters::from_bytes(&array)?;

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[8..40]);
        let dh_private_key = DHPrivateKey::from_bytes(&array)?;

        array.copy_from_slice(&bytes[40..72]);
        let dh_public_key = DHPublicKey::from_bytes(&array)?;
        
        let commit_len = u32::from_le_bytes(
            bytes[72..76]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );
        let mut their_commitments: Vec<VerifiableSecretSharingCommitment> = 
            Vec::with_capacity(commit_len as usize);

        let mut index_slice = 76 as usize;
        for _ in 0..commit_len {
            let verifiable_commitment = VerifiableSecretSharingCommitment::from_bytes(&bytes[index_slice..])?;
            their_commitments.push(verifiable_commitment.clone());
            index_slice += 8 + verifiable_commitment.points.len() * 32;
        }

        let dh_key_len = u32::from_le_bytes(
            bytes[index_slice..index_slice+4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );
        let mut their_dh_public_keys: Vec<(u32, DHPublicKey)> = 
            Vec::with_capacity(dh_key_len as usize);

        index_slice += 4;
        for _ in 0..dh_key_len {
            let index = u32::from_le_bytes(
                bytes[index_slice..index_slice+4]
                    .try_into()
                    .map_err(|_| Error::SerialisationError)?,
            );
            let key = DHPublicKey::from_bytes(&bytes[index_slice+4..index_slice+36])?;
            their_dh_public_keys.push((index, key));
            index_slice += 36;
        }

        let my_secret_share = SecretShare::from_bytes(&bytes[index_slice..index_slice+40])?;
        index_slice += 40;

        let their_encrypted_secret_shares = match bytes[index_slice] {
            1u8 => {
                index_slice += 1;
                let shares_len = u32::from_le_bytes(
                    bytes[index_slice..index_slice+4]
                        .try_into()
                        .map_err(|_| Error::SerialisationError)?,
                );
                let mut encrypted_shares: Vec<EncryptedSecretShare> = 
                    Vec::with_capacity(shares_len as usize);
        
                index_slice += 4;
                for _ in 0..shares_len {
                    let share = EncryptedSecretShare::from_bytes(&bytes[index_slice..index_slice+56])?;
                    encrypted_shares.push(share);
                    index_slice += 56;
                }

                Some(encrypted_shares)
            },
            0u8 => {
                index_slice += 1;
                None
            },
            _ => return Err(Error::SerialisationError),
        };

        let my_secret_shares = match bytes[index_slice] {
            1u8 => {
                index_slice += 1;
                let shares_len = u32::from_le_bytes(
                    bytes[index_slice..index_slice+4]
                        .try_into()
                        .map_err(|_| Error::SerialisationError)?,
                );
                let mut shares: Vec<SecretShare> = 
                    Vec::with_capacity(shares_len as usize);
        
                index_slice += 4;
                for _ in 0..shares_len {
                    let share = SecretShare::from_bytes(&bytes[index_slice..index_slice+40])?;
                    shares.push(share);
                    index_slice += 40;
                }

                Some(shares)
            },
            0u8 => {
                None
            },
            _ => return Err(Error::SerialisationError),
        };

        Ok(ActualState {
            parameters,
            dh_private_key,
            dh_public_key,
            Some(their_commitments),
            their_dh_public_keys,
            their_encrypted_secret_shares,
            my_secret_shares,
        })
    }
    */
}

/// Marker trait to designate valid rounds in the distributed key generation
/// protocol's state machine.  It is implemented using the [sealed trait design
/// pattern][sealed] pattern to prevent external types from implementing further
/// valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait DkgState: private::Sealed {}

impl DkgState for RoundOne {}
impl DkgState for RoundTwo {}

/// Marker trait to designate valid variants of [`RoundOne`] in the distributed
/// key generation protocol's state machine.  It is implemented using the
/// [sealed trait design pattern][sealed] pattern to prevent external types from
/// implementing further valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Round1: private::Sealed {}

/// Marker trait to designate valid variants of [`RoundTwo`] in the distributed
/// key generation protocol's state machine.  It is implemented using the
/// [sealed trait design pattern][sealed] pattern to prevent external types from
/// implementing further valid states.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed
pub trait Round2: private::Sealed {}

impl Round1 for RoundOne {}
impl Round2 for RoundTwo {}

fn encrypt_share(share: &SecretShare, aes_key: &[u8; 32]) -> EncryptedSecretShare {
    let hkdf = Hkdf::<Sha512>::new(None, &aes_key[..]);
    let mut final_aes_key = [0u8; 32];
    hkdf.expand(&[], &mut final_aes_key)
        .expect("KDF expansion failed unexpectedly");

    let mut rng: OsRng = OsRng;
    let mut nonce_array = [0u8; 16];
    rng.fill_bytes(&mut nonce_array);

    let final_aes_key = GenericArray::from_slice(&final_aes_key);
    let mut share_bytes = share.polynomial_evaluation.to_bytes();

    let nonce = GenericArray::from_slice(&nonce_array);
    let cipher = Aes256::new(&final_aes_key);
    let mut cipher = Aes256Ctr::from_block_cipher(cipher, &nonce);

    cipher.apply_keystream(&mut share_bytes);

    EncryptedSecretShare {
        sender_index: share.sender_index,
        receiver_index: share.receiver_index,
        nonce: nonce_array,
        encrypted_polynomial_evaluation: share_bytes,
    }
}

fn decrypt_share(encrypted_share: &EncryptedSecretShare, aes_key: &[u8; 32]) -> Result<SecretShare, Error> {
    let hkdf = Hkdf::<Sha512>::new(None, &aes_key[..]);
    let mut final_aes_key = [0u8; 32];
    hkdf.expand(&[], &mut final_aes_key)
        .expect("KDF expansion failed unexpectedly");

    let final_aes_key = GenericArray::from_slice(&final_aes_key);

    let nonce = GenericArray::from_slice(&encrypted_share.nonce);
    let cipher = Aes256::new(&final_aes_key);
    let mut cipher = Aes256Ctr::from_block_cipher(cipher, &nonce);

    let mut bytes: [u8; 32] = encrypted_share.encrypted_polynomial_evaluation;
    cipher.apply_keystream(&mut bytes);

    let evaluation = Scalar::from_canonical_bytes(bytes);
    if evaluation.is_none() {return Err(Error::DecryptionError)}

    Ok(SecretShare { sender_index: encrypted_share.sender_index,
                     receiver_index: encrypted_share.receiver_index, 
                     polynomial_evaluation: evaluation.unwrap() })
}

/// Every participant in the distributed key generation has sent a vector of
/// commitments and a zero-knowledge proof of a secret key to every other
/// participant in the protocol.  During round one, each participant checks the
/// zero-knowledge proofs of secret keys of all other participants.
#[derive(Clone, Debug)]
pub struct RoundOne {}

impl DistributedKeyGeneration<RoundOne> {
    /// Check the zero-knowledge proofs of knowledge of secret keys of all the
    /// other participants.
    ///
    /// # Note
    ///
    /// The `participants` will be sorted by their indices.
    ///
    /// # Returns
    ///
    /// An updated state machine for the distributed key generation protocol if
    /// all of the zero-knowledge proofs verified successfully, otherwise a
    /// vector of participants whose zero-knowledge proofs were incorrect.
    pub fn new_dealer_state(
        parameters: &Parameters,
        dh_private_key: &DHPrivateKey,
        my_index: &u32,
        my_coefficients: &Coefficients,
        signers: &mut Vec<Participant>,
        context_string: &str,
    ) -> Result<Self, Vec<u32>>
    {
        let mut their_commitments: Vec<VerifiableSecretSharingCommitment> = Vec::with_capacity(parameters.t as usize);
        let mut their_dh_public_keys: Vec<(u32, DHPublicKey)> = Vec::with_capacity(parameters.t as usize);
        let mut misbehaving_signers: Vec<u32> = Vec::new();

        let dh_public_key = DHPublicKey(&RISTRETTO_BASEPOINT_TABLE * &dh_private_key);

        // Bail if we didn't get enough signers.
        if signers.len() != parameters.n as usize - 1 {
            return Err(misbehaving_signers);
        }

        // Step 5: Upon receiving C_l, \sigma_l from signers 1 \le l \le n, l \ne i,
        //         participant P_i verifies \sigma_l = (s_l, r_l), by checking:
        //
        //         s_l ?= H(l, \Phi, \phi_{l0}, g^{r_l} \mdot \phi_{l0}^{-s_i})
        for p in signers.iter() {
            let public_key = match p.public_key() {
                Some(key) => key,
                None      => {
                    misbehaving_signers.push(p.index);
                    continue;
                }
            };
            match p.proof_of_secret_key.as_ref().unwrap().verify(&p.index, &public_key, &context_string) {
                Ok(_)  => {
                            their_commitments.push(p.commitments.as_ref().unwrap().clone());
                            their_dh_public_keys.push((p.index, p.dh_public_key.clone()));

                            match p.proof_of_dh_private_key.verify(&p.index, &p.dh_public_key, &context_string) {
                                Ok(_)  => (),
                                Err(_) => misbehaving_signers.push(p.index),
                            }
                          },
                Err(_) => misbehaving_signers.push(p.index),
            }
        }

        // [DIFFERENT_TO_PAPER] If any participant was misbehaving, return their indices.
        if !misbehaving_signers.is_empty() {
            return Err(misbehaving_signers);
        }

        // [DIFFERENT_TO_PAPER] We pre-calculate the secret shares from Round 2
        // Step 1 here since it doesn't require additional online activity.
        // RICE-FROST: We also encrypt them into their_encrypted_secret_shares.
        //
        // Round 2
        // Step 1: Each P_i securely sends to each other participant P_l a secret share
        //         (l, f_i(l)) and keeps (i, f_i(i)) for themselves.
        let mut their_encrypted_secret_shares: Vec<EncryptedSecretShare> = Vec::with_capacity(parameters.n as usize - 1);

        // XXX need a way to index their_encrypted_secret_shares
        for p in signers.iter() {
            let share = SecretShare::evaluate_polynomial(my_index, &p.index, my_coefficients);

            let dh_key = (p.dh_public_key.0 * dh_private_key.0).compress().to_bytes();

            their_encrypted_secret_shares.push(encrypt_share(&share, &dh_key));
        }

        let state = ActualState {
            parameters: *parameters,
            index: *my_index,
            dh_private_key: dh_private_key.clone(),
            dh_public_key,
            their_commitments: Some(their_commitments),
            their_dh_public_keys,
            their_encrypted_secret_shares: Some(their_encrypted_secret_shares),
            my_secret_shares: None,
        };

        Ok(DistributedKeyGeneration::<RoundOne> {
            state: Box::new(state),
            data: RoundOne {},
        })
    }

    /// Check the zero-knowledge proofs of knowledge of secret keys of all the
    /// other participants.
    ///
    /// # Note
    ///
    /// The `participants` will be sorted by their indices.
    ///
    /// # Returns
    ///
    /// An updated state machine for the distributed key generation protocol if
    /// all of the zero-knowledge proofs verified successfully, otherwise a
    /// vector of participants whose zero-knowledge proofs were incorrect.
    pub fn new_signer_state(
        parameters: &Parameters,
        dh_private_key: &DHPrivateKey,
        my_index: &u32,
        dealers: &mut Vec<Participant>,
        context_string: &str,
    ) -> Result<Self, Vec<u32>>
    {
        let mut their_dh_public_keys: Vec<(u32, DHPublicKey)> = Vec::with_capacity(parameters.t as usize);
        let mut misbehaving_dealers: Vec<u32> = Vec::new();

        let dh_public_key = DHPublicKey(&RISTRETTO_BASEPOINT_TABLE * &dh_private_key);

        // Bail if we didn't get enough dealers.
        if dealers.len() != parameters.n as usize - 1 {
            return Err(misbehaving_dealers);
        }

        // Step 5: Upon receiving C_l, \sigma_l from dealers 1 \le l \le n, l \ne i,
        //         participant P_i verifies \sigma_l = (s_l, r_l), by checking:
        //
        //         s_l ?= H(l, \Phi, \phi_{l0}, g^{r_l} \mdot \phi_{l0}^{-s_i})
        for p in dealers.iter() {
            their_dh_public_keys.push((p.index, p.dh_public_key.clone()));
            match p.proof_of_dh_private_key.verify(&p.index, &p.dh_public_key, &context_string) {
                Ok(_)  => (),
                Err(_) => misbehaving_dealers.push(p.index),
            }
        }

        // [DIFFERENT_TO_PAPER] If any participant was misbehaving, return their indices.
        if !misbehaving_dealers.is_empty() {
            return Err(misbehaving_dealers);
        }

        let state = ActualState {
            parameters: *parameters,
            index: *my_index,
            dh_private_key: dh_private_key.clone(),
            dh_public_key,
            their_commitments: None,
            their_dh_public_keys,
            their_encrypted_secret_shares: None,
            my_secret_shares: None,
        };

        Ok(DistributedKeyGeneration::<RoundOne> {
            state: Box::new(state),
            data: RoundOne {},
        })
    }

    /// Retrieve an encrypted secret share for each other participant, to be given to them
    /// at the end of `DistributedKeyGeneration::<RoundOne>`.
    pub fn their_encrypted_secret_shares(&self) -> Result<&Vec<EncryptedSecretShare>, ()> {
        self.state.their_encrypted_secret_shares.as_ref().ok_or(())
    }

    /// Progress to round two of the DKG protocol once we have sent each encrypted share
    /// from `DistributedKeyGeneration::<RoundOne>.their_encrypted_secret_shares()` to its
    /// respective other participant, and collected our shares from the other
    /// participants in turn.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_round_two(
        mut self,
        my_encrypted_secret_shares: Vec<EncryptedSecretShare>,
    ) -> Result<DistributedKeyGeneration<RoundTwo>, Error>
    {
        // Zero out the other participants encrypted secret shares from memory.
        if self.state.their_encrypted_secret_shares.is_some() {
            self.state.their_encrypted_secret_shares.unwrap().zeroize();
            // XXX Does setting this to None always call drop()?
            self.state.their_encrypted_secret_shares = None;
        }

        // RICE-FROST

        let mut complaints: Vec<Complaint> = Vec::new();
        
        if my_encrypted_secret_shares.len() != self.state.parameters.n as usize - 1 {
            return Err(Error::MissingShares);
        }

        let mut my_secret_shares: Vec<SecretShare> = Vec::new();

        // Step 2.1: Each P_i decrypts their shares with
        //           key k_il = pk_l^sk_i
        for encrypted_share in my_encrypted_secret_shares.iter(){
            for pk in self.state.their_dh_public_keys.iter(){
                if pk.0 == encrypted_share.sender_index {
                    let dh_key = (*pk.1 * self.state.dh_private_key.0).compress().to_bytes();

                    // Step 2.2: Each share is verified by calculating:
                    //           g^{f_l(i)} ?= \Prod_{k=0}^{t-1} \phi_{lk}^{i^{k} mod q},
                    //           creating a complaint if the check fails.
                    let decrypted_share = decrypt_share(&encrypted_share, &dh_key);
                    let decrypted_share_ref = &decrypted_share;
                    
                    for commitment in self.state.their_commitments.as_ref().unwrap().iter() {
                        if commitment.index == encrypted_share.sender_index {
                            // If the decrypted share is incorrect, P_i builds
                            // a complaint

                            if decrypted_share.is_err() || decrypted_share_ref.as_ref().unwrap().verify(commitment).is_err() {

                                let mut rng: OsRng = OsRng;
                                let r = Scalar::random(&mut rng);

                                let a1 = &RISTRETTO_BASEPOINT_TABLE * &r;
                                let a2 = *pk.1 * r;

                                let mut h = Sha512::new();
                                h.update(self.state.dh_public_key.compress().to_bytes());
                                h.update(pk.1.compress().to_bytes());
                                h.update(dh_key);
                                h.update(a1.compress().to_bytes());
                                h.update(a2.compress().to_bytes());

                                let h = Scalar::from_hash(h);

                                complaints.push(
                                    Complaint {
                                        maker_index: encrypted_share.receiver_index,
                                        accused_index: pk.0,
                                        dh_key,
                                        proof: ComplaintProof {
                                            a1,
                                            a2,
                                            z: r + h * self.state.dh_private_key.0,
                                        }
                                    }
                                );
                                break;
                            }
                        }
                    }
                    if let Ok(share) = decrypted_share {
                        my_secret_shares.push(share);
                    }
                }
            }
        }

        if !complaints.is_empty() {
            return Err(Error::Complaint(complaints))
        }

        self.state.my_secret_shares = Some(my_secret_shares);

        Ok(DistributedKeyGeneration::<RoundTwo> {
            state: self.state,
            data: RoundTwo {},
        })
    }

    /* MUST IMPLEMENT SERIALISATION METHODS
    /// Serialise this DKG to a Vec of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res = self.state.to_bytes();
        res.push(1u8);

        res
    }

    /// Deserialise this slice of bytes to a `DistributedKeyGeneration::<RoundOne>`
    pub fn from_bytes(bytes: &[u8]) -> Result<DistributedKeyGeneration::<RoundOne>, Error> {
        let state = ActualState::from_bytes(&bytes)?;
        let data = if bytes[bytes.len() - 1] == 1 {
            RoundOne {}
        } else {
            return Err(Error::SerialisationError)
        };

        Ok(
            DistributedKeyGeneration::<RoundOne> {
                state: Box::new(state),
                data,
            }
        )
    }
    */
}

/// A secret share calculated by evaluating a polynomial with secret
/// coefficients for some indeterminant.
#[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct SecretShare {
    /// The index of the share maker.
    pub sender_index: u32,
    /// The participant index that this secret share was calculated for.
    pub receiver_index: u32,
    /// The final evaluation of the polynomial for the participant-respective
    /// indeterminant.
    pub(crate) polynomial_evaluation: Scalar,
}

impl SecretShare {
    /// Evaluate the polynomial, `f(x)` for the secret coefficients at the value of `x`.
    //
    // XXX [PAPER] [CFRG] The participant index CANNOT be 0, or the secret share ends up being Scalar::zero().
    pub(crate) fn evaluate_polynomial(sender_index: &u32, receiver_index: &u32, coefficients: &Coefficients) -> SecretShare {
        let term: Scalar = (*receiver_index).into();
        let mut sum: Scalar = Scalar::zero();

        // Evaluate using Horner's method.
        for (receiver_index, coefficient) in coefficients.0.iter().rev().enumerate() {
            // The secret is the constant term in the polynomial
            sum += coefficient;

            if receiver_index != (coefficients.0.len() - 1) {
                sum *= term;
            }
        }
        SecretShare { sender_index: *sender_index, receiver_index: *receiver_index, polynomial_evaluation: sum }
    }

    /// Verify that this secret share was correctly computed w.r.t. some secret
    /// polynomial coefficients attested to by some `commitment`.
    pub(crate) fn verify(&self, commitment: &VerifiableSecretSharingCommitment) -> Result<(), Error> {
        let lhs = &RISTRETTO_BASEPOINT_TABLE * &self.polynomial_evaluation;
        let term: Scalar = self.receiver_index.into();
        let mut rhs: RistrettoPoint = RistrettoPoint::identity();

        for (index, com) in commitment.points.iter().rev().enumerate() {
            rhs += com;

            if index != (commitment.points.len() - 1) {
                rhs *= term;
            }
        }

        match lhs.compress() == rhs.compress() {
            true => Ok(()),
            false => Err(Error::ShareVerificationError),
        }
    }

    /// Serialise this secret share to an array of bytes
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut res = [0u8; 40];
        res[0..4].copy_from_slice(&mut self.sender_index.to_le_bytes());
        res[4..8].copy_from_slice(&mut self.receiver_index.to_le_bytes());
        res[8..40].copy_from_slice(&mut self.polynomial_evaluation.to_bytes());

        res
    }

    /// Deserialise this slice of bytes to a `SecretShare`
    pub fn from_bytes(bytes: &[u8]) -> Result<SecretShare, Error> {
        let sender_index = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );

        let receiver_index = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[8..40]);
        let polynomial_evaluation = Scalar::from_canonical_bytes(array)
                .ok_or(Error::SerialisationError)?;

        Ok(SecretShare {
            sender_index,
            receiver_index,
            polynomial_evaluation,
        })
    }
}


/// A secret share encrypted with a participant's public key
#[derive(Clone, Debug, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct EncryptedSecretShare {
    /// The index of the share maker.
    pub sender_index: u32,
    /// The participant index that this secret share was calculated for.
    pub receiver_index: u32,
    /// The nonce to be used for decryption with AES-CTR mode.
    pub nonce: [u8; 16],
    /// The encrypted polynomial evaluation.
    pub(crate) encrypted_polynomial_evaluation: [u8; 32],
}

impl EncryptedSecretShare {
    /// Serialise this encrypted secret share to an array of bytes
    pub fn to_bytes(&self) -> [u8; 56] {
        let mut res = [0u8; 56];
        res[0..4].copy_from_slice(&mut self.sender_index.to_le_bytes());
        res[4..8].copy_from_slice(&mut self.receiver_index.to_le_bytes());
        res[8..24].copy_from_slice(&mut self.nonce.clone());
        res[24..56].copy_from_slice(&mut self.encrypted_polynomial_evaluation.clone());

        res
    }

    /// Deserialise this slice of bytes to a `EncryptedSecretShare`
    pub fn from_bytes(bytes: &[u8]) -> Result<EncryptedSecretShare, Error> {
        let sender_index = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );
        let receiver_index = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );
        let nonce = bytes[8..24]
            .try_into()
            .map_err(|_| Error::SerialisationError)?;
        let encrypted_polynomial_evaluation = bytes[24..56]
            .try_into()
            .map_err(|_| Error::SerialisationError)?;

        Ok(EncryptedSecretShare {
            sender_index,
            receiver_index,
            nonce,
            encrypted_polynomial_evaluation,
        })
    }
}

/// A proof that a generated complaint is valid. 
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ComplaintProof {
    /// a1 = g^r.
    pub a1: RistrettoPoint,
    /// a2 = pk_l^r.
    pub a2: RistrettoPoint,
    /// z = r + H(pk_i, pk_l, k_il).sh_i
    pub z: Scalar,
}

impl ComplaintProof {
    /// Serialise this complaint proof to an array of bytes
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut res = [0u8; 96];
        res[0..32].copy_from_slice(&mut self.a1.compress().to_bytes());
        res[32..64].copy_from_slice(&mut self.a2.compress().to_bytes());
        res[64..96].copy_from_slice(&mut self.z.to_bytes());

        res
    }

    /// Deserialise this slice of bytes to a `ComplaintProof`
    pub fn from_bytes(bytes: &[u8]) -> Result<ComplaintProof, Error> {
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[0..32]);
        let a1 = CompressedRistretto(array)
            .decompress()
            .ok_or(Error::SerialisationError)?;

        array.copy_from_slice(&bytes[32..64]);
        let a2 = CompressedRistretto(array)
            .decompress()
            .ok_or(Error::SerialisationError)?;

        array.copy_from_slice(&bytes[64..96]);
        let z = Scalar::from_canonical_bytes(array)
                .ok_or(Error::SerialisationError)?;

        Ok(ComplaintProof { a1, a2, z })
    }
}

/// A complaint generated when a participant receives a bad share.
#[derive(Clone, Debug, PartialEq)]
pub struct Complaint {
    /// The index of the complaint maker.
    pub maker_index: u32,
    /// The index of the alleged misbehaving participant.
    pub accused_index: u32,
    /// The shared DH key.
    pub dh_key: [u8; 32],
    /// The complaint proof.
    pub proof: ComplaintProof,
}

impl Complaint {
    /// A complaint is valid if:
    /// --  a1 + h.pk_i = z.g
    /// --  a2 + h.k_il = z.pk_l
    pub fn verify(
        &self, 
        pk_i: &RistrettoPoint,
        pk_l: &RistrettoPoint,
    ) -> Result<(), Error> {
        let mut h = Sha512::new();
        h.update(pk_i.compress().to_bytes());
        h.update(pk_l.compress().to_bytes());
        h.update(self.dh_key);
        h.update(self.proof.a1.compress().to_bytes());
        h.update(self.proof.a2.compress().to_bytes());

        let h = Scalar::from_hash(h);

        if self.proof.a1 + pk_i * h != &RISTRETTO_BASEPOINT_TABLE * &self.proof.z {
            return Err(Error::ComplaintVerificationError)
        }

        if let Some(key_as_point) = CompressedRistretto::from_slice(&self.dh_key).decompress() {
            if self.proof.a2 + key_as_point * h != pk_l * self.proof.z {
                return Err(Error::ComplaintVerificationError)
            }
        } else {
            return Err(Error::ComplaintVerificationError)
        }

        Ok(())
    }

    /// Serialise this complaint to an array of bytes
    pub fn to_bytes(&self) -> [u8; 136] {
        let mut res = [0u8; 136];
        res[0..4].copy_from_slice(&mut self.maker_index.to_le_bytes());
        res[4..8].copy_from_slice(&mut self.accused_index.to_le_bytes());
        res[8..40].copy_from_slice(&mut self.dh_key.clone());
        res[40..136].copy_from_slice(&mut self.proof.to_bytes());

        res
    }

    /// Deserialise this slice of bytes to a `Complaint`
    pub fn from_bytes(bytes: &[u8]) -> Result<Complaint, Error> {
        let maker_index = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );
        let accused_index = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );
        let dh_key = bytes[8..40]
            .try_into()
            .map_err(|_| Error::SerialisationError)?;
        let proof = ComplaintProof::from_bytes(&bytes[40..136])?;

        Ok(Complaint {
            maker_index,
            accused_index,
            dh_key,
            proof,
        })
    }
}

/// During round two each participant verifies their secret shares they received
/// from each other participant.
#[derive(Clone, Debug)]
pub struct RoundTwo {}

impl DistributedKeyGeneration<RoundTwo> {
    /// Calculate this threshold signing protocol participant's long-lived
    /// secret signing keyshare and the group's public verification key.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let (group_key, secret_key) = state.finish(participant.public_key()?)?;
    /// ```
    pub fn finish(mut self, my_commitment: Vec<RistrettoPoint>) -> Result<(GroupKey, SecretKey), Error> {
        let secret_key = self.calculate_signing_key()?;
        let group_key = self.calculate_group_key(my_commitment)?;

        self.state.my_secret_shares.zeroize();

        Ok((group_key, secret_key))
    }

    /// Calculate this threshold signing participant's long-lived secret signing
    /// key by interpolating all of the polynomial evaluations from the other
    /// participants.
    pub(crate) fn calculate_signing_key(&self) -> Result<SecretKey, Error> {
        let my_secret_shares = self.state.my_secret_shares
            .as_ref()
            .ok_or(Error::Custom("Could not retrieve participant's secret shares".to_string()))?;

        let mut index_vector: Vec<u32> = Vec::new();

        for share in my_secret_shares.iter() {
            index_vector.push(share.sender_index);
        }

        // This time you don't use your own index!
        // index_vector.push(self.state.my_secret_share.sender_index);

        let mut key = Scalar::zero();

        for share in my_secret_shares.iter() {
            let coeff = match calculate_lagrange_coefficients(&share.sender_index, &index_vector) {
                Ok(s) => s,
                Err(error) => return Err(Error::Custom(error.to_string())),
            };
            key += share.polynomial_evaluation * coeff;
        }

        // You don't use your secret share in the computation.
        /* let my_coeff = match calculate_lagrange_coefficients(&self.state.my_secret_share.sender_index, &index_vector) {
                Ok(s) => s,
                Err(error) => return Err(Error::Custom(error.to_string())),
            };

        key += self.state.my_secret_share.polynomial_evaluation * my_coeff; */

        Ok(SecretKey { index: self.state.index, key })
    }

    /// Calculate the group public key used for verifying threshold signatures.
    ///
    /// # Returns
    ///
    /// A [`GroupKey`] for the set of participants.
    ///
    /// my_commitment is needed for now, but won't be when the distinction 
    /// dealers/signers is implemented.
    pub(crate) fn calculate_group_key(&self, my_commitment: Vec<RistrettoPoint>) -> Result<GroupKey, Error> {

        let mut index_vector: Vec<u32> = Vec::new();

        for commitment in self.state.their_commitments.as_ref().unwrap().iter() {
            index_vector.push(commitment.index);
        }

        // This time you don't use your own index!
        // index_vector.push(self.state.my_secret_share.sender_index);

        let all_commitments = self.state.their_commitments.as_ref().unwrap().clone();
        // all_commitments.push((self.state.my_secret_share.sender_index, VerifiableSecretSharingCommitment(my_commitment)));

        let mut group_key = RistrettoPoint::identity();

        // The group key is the interpolation at 0 of all verification shares.
        for i in index_vector.iter() {

            let mut public_verif_share = RistrettoPoint::identity();

            // Verification share for participant i is the interpolation of its secret shares' hidings.
            // A secret share hiding can be evaluated with the sender's commitment and the Horner method.
            for commitment in all_commitments.iter() {

                let term: Scalar = (*i).into();
                let internal_coeff = match calculate_lagrange_coefficients(&commitment.index, &index_vector) {
                    Ok(s) => s,
                    Err(error) => return Err(Error::Custom(error.to_string())),
                };
                public_verif_share += internal_coeff * commitment.evaluate_hiding(&term);
                    
            }

            let external_coeff = match calculate_lagrange_coefficients(&i, &index_vector) {
                Ok(s) => s,
                Err(error) => return Err(Error::Custom(error.to_string())),
            };
            group_key += external_coeff * public_verif_share; 
        }

        Ok(GroupKey(group_key))
    }


    /// Every participant can verify a complaint and determine who is the malicious
    /// party. The relevant encrypted share is assumed to exist and publicly retrievable
    /// by any participant.
    pub fn blame(
        &self,
        encrypted_share: &EncryptedSecretShare,
        complaint: &Complaint,
    ) -> u32 {
        let mut pk_maker = RistrettoPoint::identity();
        let mut pk_accused = RistrettoPoint::identity();
        let mut commitment_accused = VerifiableSecretSharingCommitment { index: 0, points: Vec::new() };

        for commitment in self.state.their_commitments.as_ref().unwrap().iter() {
            if commitment.index == complaint.accused_index {
                commitment_accused = commitment.clone();
            }
        }

        if commitment_accused.points.is_empty() {
            return complaint.maker_index;
        }

        for (index, pk) in self.state.their_dh_public_keys.iter() {
            if index == &complaint.maker_index {
                pk_maker = **pk;
            }

            else if index == &complaint.accused_index {
                pk_accused = **pk;
            }
        };

        if pk_maker == RistrettoPoint::identity() || pk_accused == RistrettoPoint::identity() {
            return complaint.maker_index
        }

        if complaint.verify(&pk_maker, &pk_accused).is_err() {
            return complaint.maker_index
        }

        let share = decrypt_share(encrypted_share, &complaint.dh_key);
        if share.is_err() {
            return complaint.accused_index
        }
        match share.unwrap().verify(&commitment_accused) {
            Ok(()) => complaint.maker_index,
            Err(_) => complaint.accused_index,
        }
    }

    /* MUST IMPLEMENT SERIALISATION METHODS
    /// Serialise this DKG to a Vec of bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut res = self.state.to_bytes();
        res.push(2u8);

        res
    }

    /// Deserialise this slice of bytes to a `DistributedKeyGeneration::<RoundTwo>`
    pub fn from_bytes(bytes: &[u8]) -> Result<DistributedKeyGeneration::<RoundTwo>, Error> {
        let state = ActualState::from_bytes(&bytes)?;
        let data = if bytes[bytes.len() - 1] == 2 {
            RoundTwo {}
        } else {
            return Err(Error::SerialisationError)
        };

        Ok(
            DistributedKeyGeneration::<RoundTwo> {
                state: Box::new(state),
                data,
            }
        )
    }
    */
}

/// A public verification share for a participant.
///
/// Any participant can recalculate the public verification share, which is the
/// public half of a [`SecretKey`], of any other participant in the protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndividualPublicKey {
    /// The participant index to which this key belongs.
    pub index: u32,
    /// The public verification share.
    pub share: RistrettoPoint,
}

impl IndividualPublicKey {
    /// Any participant can compute the public verification share of any other participant.
    ///
    /// This is done by re-computing each [`IndividualPublicKey`] as \\(Y\_i\\) s.t.:
    ///
    /// \\[
    /// Y\_i = \prod\_{j=1}^{n} \prod\_{k=0}^{t-1} \phi\_{jk}^{i^{k} \mod q}
    /// \\]
    ///
    /// for each [`Participant`] index \\(i\\).
    ///
    /// # Inputs
    ///
    /// * A vector of `commitments` regarding the secret polynomial
    ///   [`Coefficients`] that this [`IndividualPublicKey`] was generated with.
    ///
    /// # Returns
    ///
    /// A `Result` with either an empty `Ok` or `Err` value, depending on
    /// whether or not the verification was successful.
    pub fn verify(
        &self,
        commitments: &[VerifiableSecretSharingCommitment],
    ) -> Result<(), Error>
    {
        let mut rhs: RistrettoPoint = RistrettoPoint::identity();
        let term: Scalar = self.index.into();

        for commitment in commitments.iter() {
            let mut tmp: RistrettoPoint = RistrettoPoint::identity();
            for (index, com) in commitment.points.iter().rev().enumerate() {
                tmp += com;

                if index != (commitment.points.len() - 1) {
                    tmp *= term;
                }
            }
            rhs += tmp;
        }

        match self.share.compress() == rhs.compress() {
            true => Ok(()),
            false => Err(Error::ShareVerificationError),
        }
    }

    /// Any participant can compute the public verification share of any other participant.
    ///
    /// This is done by re-computing each [`IndividualPublicKey`] as \\(Y\_i\\) s.t.:
    ///
    /// \\[
    /// Y\_i = \prod\_{j=1}^{n} \prod\_{k=0}^{t-1} \phi\_{jk}^{i^{k} \mod q}
    /// \\]
    ///
    /// for each [`Participant`] index \\(i\\).
    ///
    /// # Inputs
    ///
    /// * A `participant_index` and
    /// * A vector of `commitments` regarding the secret polynomial
    ///   [`Coefficients`] that the [`IndividualPublicKey`] will be generated from.
    ///
    /// # Returns
    ///
    /// An `IndividualPublicKey`.
    pub fn generate_from_commitments(
        participant_index: u32,
        commitments: &[VerifiableSecretSharingCommitment],
    ) -> Self
    {
        let mut share: RistrettoPoint = RistrettoPoint::identity();
        let term: Scalar = participant_index.into();

        for commitment in commitments.iter() {
            let mut tmp: RistrettoPoint = RistrettoPoint::identity();
            for (index, com) in commitment.points.iter().rev().enumerate() {
                tmp += com;

                if index != (commitment.points.len() - 1) {
                    tmp *= term;
                }
            }
            share += tmp;
        }

        IndividualPublicKey {
            index: participant_index,
            share,
        }
    }

    /// Serialise this individual public key to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut res = [0u8; 36];
        res[0..4].copy_from_slice(&self.index.to_le_bytes());
        res[4..36].copy_from_slice(&self.share.compress().to_bytes());

        res
    }

    /// Deserialise this individual public key from an array of bytes.
    pub fn from_bytes(bytes: [u8; 36]) -> Result<IndividualPublicKey, Error> {
        let index = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[4..36]);
        let share = CompressedRistretto(array)
            .decompress()
            .ok_or(Error::SerialisationError)?;

        Ok(IndividualPublicKey { index, share })
    }
}

/// A secret key, used by one participant in a threshold signature scheme, to sign a message.
#[derive(Debug, Eq, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct SecretKey {
    /// The participant index to which this key belongs.
    pub(crate) index: u32,
    /// The participant's long-lived secret share of the group signing key.
    pub(crate) key: Scalar,
}

impl SecretKey {
    /// Derive the corresponding public key for this secret key.
    pub fn to_public(&self) -> IndividualPublicKey {
        let share = &RISTRETTO_BASEPOINT_TABLE * &self.key;

        IndividualPublicKey {
            index: self.index,
            share,
        }
    }

    /// Serialise this secret key to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut res = [0u8; 36];
        res[0..4].copy_from_slice(&self.index.to_le_bytes());
        res[4..36].copy_from_slice(&self.key.to_bytes());

        res
    }

    /// Deserialise this secret key from an array of bytes.
    pub fn from_bytes(bytes: [u8; 36]) -> Result<SecretKey, Error> {
        let index = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[4..36]);
        let key = Scalar::from_canonical_bytes(array)
            .ok_or(Error::SerialisationError)?;

        Ok(SecretKey { index, key })
    }
}

impl From<&SecretKey> for IndividualPublicKey {
    fn from(source: &SecretKey) -> IndividualPublicKey {
        source.to_public()
    }
}

/// A public key, used to verify a signature made by a threshold of a group of participants.
#[derive(Clone, Copy, Debug, Eq)]
pub struct GroupKey(pub(crate) RistrettoPoint);

impl PartialEq for GroupKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.compress() == other.0.compress()
    }
}

impl GroupKey {
    /// Serialise this group public key to an array of bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }

    /// Deserialise this group public key from an array of bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<GroupKey, Error> {
        let point = CompressedRistretto(bytes).decompress().ok_or(Error::SerialisationError)?;

        Ok(GroupKey(point))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;

    #[test]
    fn nizk_of_secret_key() {
        let params = Parameters { n: 3, t: 2 };
        let (p, _, _) = Participant::new_dealer(&params, 0, None, "Φ");
        let result = p.proof_of_secret_key.as_ref().unwrap().verify(&p.index, &p.public_key().unwrap(), "Φ");

        assert!(result.is_ok());
    }

    #[test]
    fn secret_share_from_one_coefficients() {
        let mut coeffs: Vec<Scalar> = Vec::new();

        for _ in 0..5 {
            coeffs.push(Scalar::one());
        }

        let coefficients = Coefficients(coeffs);
        let share = SecretShare::evaluate_polynomial(&1, &1, &coefficients);

        assert!(share.polynomial_evaluation == Scalar::from(5u8));

        let mut commitments = VerifiableSecretSharingCommitment { index: 1, points: Vec::new() };

        for i in 0..5 {
            commitments.points.push(&RISTRETTO_BASEPOINT_TABLE * &coefficients.0[i]);
        }

        assert!(share.verify(&commitments).is_ok());
    }

    #[test]
    fn secret_share_participant_index_zero() {
        let mut coeffs: Vec<Scalar> = Vec::new();

        for _ in 0..5 {
            coeffs.push(Scalar::one());
        }

        let coefficients = Coefficients(coeffs);
        let share = SecretShare::evaluate_polynomial(&1, &0, &coefficients);

        assert!(share.polynomial_evaluation == Scalar::one());

        let mut commitments = VerifiableSecretSharingCommitment { index: 1, points: Vec::new() };

        for i in 0..5 {
            commitments.points.push(&RISTRETTO_BASEPOINT_TABLE * &coefficients.0[i]);
        }

        assert!(share.verify(&commitments).is_ok());
    }

    #[test]
    fn single_party_keygen() {
        let params = Parameters { n: 1, t: 1 };

        let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, None, "Φ");

        p1.proof_of_secret_key.as_ref().unwrap().verify(&p1.index, &p1.public_key().unwrap(), "Φ").unwrap();

        let mut p1_other_participants: Vec<Participant> = Vec::new();
        let p1_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                 &p1_dh_sk,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut p1_other_participants,
                                                                 "Φ").unwrap();
        let p1_my_encrypted_secret_shares = Vec::new();
        let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).unwrap();
        let result = p1_state.finish(p1.commitments.unwrap().points);

        assert!(result.is_ok());

        let (p1_group_key, p1_secret_key) = result.unwrap();

        assert!(p1_group_key.0.compress() == (&p1_secret_key.key * &RISTRETTO_BASEPOINT_TABLE).compress());
    }

    #[test]
    fn keygen_3_out_of_5() {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, None, "Φ");
        let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, None, "Φ");
        let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, None, "Φ");
        let (p4, p4coeffs, p4_dh_sk) = Participant::new_dealer(&params, 4, None, "Φ");
        let (p5, p5coeffs, p5_dh_sk) = Participant::new_dealer(&params, 5, None, "Φ");

        p1.proof_of_secret_key.as_ref().unwrap().verify(&p1.index, &p1.public_key().unwrap(), "Φ").unwrap();
        p2.proof_of_secret_key.as_ref().unwrap().verify(&p2.index, &p2.public_key().unwrap(), "Φ").unwrap();
        p3.proof_of_secret_key.as_ref().unwrap().verify(&p3.index, &p3.public_key().unwrap(), "Φ").unwrap();
        p4.proof_of_secret_key.as_ref().unwrap().verify(&p4.index, &p4.public_key().unwrap(), "Φ").unwrap();
        p5.proof_of_secret_key.as_ref().unwrap().verify(&p5.index, &p5.public_key().unwrap(), "Φ").unwrap();

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                 &p1_dh_sk,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut p1_other_participants,
                                                                 "Φ").unwrap();
        let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap();

        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone(), p5.clone());
        let p2_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                 &p2_dh_sk,
                                                                 &p2.index,
                                                                 &p2coeffs,
                                                                 &mut p2_other_participants,
                                                                 "Φ").unwrap();
        let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone(), p5.clone());
        let  p3_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                  &p3_dh_sk,
                                                                  &p3.index,
                                                                  &p3coeffs,
                                                                  &mut p3_other_participants,
                                                                  "Φ").unwrap();
        let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p5.clone());
        let p4_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                 &p4_dh_sk,
                                                                 &p4.index,
                                                                 &p4coeffs,
                                                                 &mut p4_other_participants,
                                                                 "Φ").unwrap();
        let p4_their_encrypted_secret_shares = p4_state.their_encrypted_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone());
        let p5_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                 &p5_dh_sk,
                                                                 &p5.index,
                                                                 &p5coeffs,
                                                                 &mut p5_other_participants,
                                                                 "Φ").unwrap();
        let p5_their_encrypted_secret_shares = p5_state.their_encrypted_secret_shares().unwrap();

        let p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(), // XXX FIXME indexing
                                       p3_their_encrypted_secret_shares[0].clone(),
                                       p4_their_encrypted_secret_shares[0].clone(),
                                       p5_their_encrypted_secret_shares[0].clone());

        let p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                       p3_their_encrypted_secret_shares[1].clone(),
                                       p4_their_encrypted_secret_shares[1].clone(),
                                       p5_their_encrypted_secret_shares[1].clone());

        let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                       p2_their_encrypted_secret_shares[1].clone(),
                                       p4_their_encrypted_secret_shares[2].clone(),
                                       p5_their_encrypted_secret_shares[2].clone());

        let p4_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[2].clone(),
                                       p2_their_encrypted_secret_shares[2].clone(),
                                       p3_their_encrypted_secret_shares[2].clone(),
                                       p5_their_encrypted_secret_shares[3].clone());

        let p5_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[3].clone(),
                                       p2_their_encrypted_secret_shares[3].clone(),
                                       p3_their_encrypted_secret_shares[3].clone(),
                                       p4_their_encrypted_secret_shares[3].clone());

        let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares).unwrap();
        let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares).unwrap();
        let p4_state = p4_state.to_round_two(p4_my_encrypted_secret_shares).unwrap();
        let p5_state = p5_state.to_round_two(p5_my_encrypted_secret_shares).unwrap();

        let (p1_group_key, p1_secret_key) = p1_state.finish(p1.commitments.unwrap().points).unwrap();
        let (p2_group_key, p2_secret_key) = p2_state.finish(p2.commitments.unwrap().points).unwrap();
        let (p3_group_key, p3_secret_key) = p3_state.finish(p3.commitments.unwrap().points).unwrap();
        let (p4_group_key, p4_secret_key) = p4_state.finish(p4.commitments.unwrap().points).unwrap();
        let (p5_group_key, p5_secret_key) = p5_state.finish(p5.commitments.unwrap().points).unwrap();

        assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
        assert!(p2_group_key.0.compress() == p3_group_key.0.compress());
        assert!(p3_group_key.0.compress() == p4_group_key.0.compress());
        assert!(p4_group_key.0.compress() == p5_group_key.0.compress());

        let mut group_secret_key = Scalar::zero();
        let indices = [1, 2, 3, 4, 5];

        group_secret_key += calculate_lagrange_coefficients(&1, &indices).unwrap()*p1_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients(&2, &indices).unwrap()*p2_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients(&3, &indices).unwrap()*p3_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients(&4, &indices).unwrap()*p4_secret_key.key;
        group_secret_key += calculate_lagrange_coefficients(&5, &indices).unwrap()*p5_secret_key.key;

        let group_key = &group_secret_key * &RISTRETTO_BASEPOINT_TABLE;

        assert!(p5_group_key.0.compress() == group_key.compress())

        // Not valid anymore
        /*
        assert!(p5_group_key.0.compress() ==
                (p1.public_key().unwrap() +
                 p2.public_key().unwrap() +
                 p3.public_key().unwrap() +
                 p4.public_key().unwrap() +
                 p5.public_key().unwrap()).compress());
        */
    }


    #[test]
    fn keygen_2_out_of_3() {
        fn do_test() -> Result<(), ()> {
            let params = Parameters { n: 3, t: 2 };

            let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, None, "Φ");
            let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, None, "Φ");
            let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, None, "Φ");

            p1.proof_of_secret_key.as_ref().unwrap().verify(&p1.index, &p1.public_key().unwrap(), "Φ").or(Err(()))?;
            p2.proof_of_secret_key.as_ref().unwrap().verify(&p2.index, &p2.public_key().unwrap(), "Φ").or(Err(()))?;
            p3.proof_of_secret_key.as_ref().unwrap().verify(&p3.index, &p3.public_key().unwrap(), "Φ").or(Err(()))?;

            let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &p1_dh_sk,
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut p1_other_participants,
                                                                     "Φ").or(Err(()))?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone());
            let p2_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &p2_dh_sk,
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut p2_other_participants,
                                                                     "Φ").or(Err(()))?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone());
            let  p3_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                      &p3_dh_sk,
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut p3_other_participants,
                                                                      "Φ").or(Err(()))?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(), // XXX FIXME indexing
                                           p3_their_encrypted_secret_shares[0].clone());
            let p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                           p3_their_encrypted_secret_shares[1].clone());
            let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                           p2_their_encrypted_secret_shares[1].clone());

            let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
            let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares).or(Err(()))?;
            let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

            let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.commitments.unwrap().points).or(Err(()))?;
            let (p2_group_key, _p2_secret_key) = p2_state.finish(p2.commitments.unwrap().points).or(Err(()))?;
            let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.commitments.unwrap().points).or(Err(()))?;

            assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
            assert!(p2_group_key.0.compress() == p3_group_key.0.compress());

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn keygen_static_2_out_of_3() {
        fn do_test() -> Result<(), ()> {
            let params = Parameters { n: 4, t: 2 };

            let (dealer1, dealer1coeffs, dealer1_dh_sk) = Participant::new_dealer(&params, 1, None, "Φ");
            let (dealer2, dealer2coeffs, dealer2_dh_sk) = Participant::new_dealer(&params, 2, None, "Φ");
            let (dealer3, dealer3coeffs, dealer3_dh_sk) = Participant::new_dealer(&params, 3, None, "Φ");

            dealer1.proof_of_secret_key.as_ref().unwrap().verify(&dealer1.index, &dealer1.public_key().unwrap(), "Φ").or(Err(()))?;
            dealer2.proof_of_secret_key.as_ref().unwrap().verify(&dealer2.index, &dealer2.public_key().unwrap(), "Φ").or(Err(()))?;
            dealer3.proof_of_secret_key.as_ref().unwrap().verify(&dealer3.index, &dealer3.public_key().unwrap(), "Φ").or(Err(()))?; 

            let (signer1, signer1_dh_sk) = Participant::new_signer(&params, 1, "Φ");
            let (signer2, signer2_dh_sk) = Participant::new_signer(&params, 2, "Φ");
            let (signer3, signer3_dh_sk) = Participant::new_signer(&params, 3, "Φ");

            signer1.proof_of_secret_key.as_ref().unwrap().verify(&signer1.index, &signer1.public_key().unwrap(), "Φ").or(Err(()))?;
            signer2.proof_of_secret_key.as_ref().unwrap().verify(&signer2.index, &signer2.public_key().unwrap(), "Φ").or(Err(()))?;
            signer3.proof_of_secret_key.as_ref().unwrap().verify(&signer3.index, &signer3.public_key().unwrap(), "Φ").or(Err(()))?; 

            let mut dealer1_signers: Vec<Participant> = vec!(signer1.clone(), signer2.clone(), signer3.clone());
            let dealer1_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &dealer1_dh_sk,
                                                                     &dealer1.index,
                                                                     &dealer1coeffs,
                                                                     &mut dealer1_signers,
                                                                     "Φ").or(Err(()))?;
            let dealer1_their_encrypted_secret_shares = dealer1_state.their_encrypted_secret_shares()?;

            let mut dealer2_signers: Vec<Participant> = vec!(signer1.clone(), signer2.clone(), signer3.clone());
            let dealer2_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &dealer2_dh_sk,
                                                                     &dealer2.index,
                                                                     &dealer2coeffs,
                                                                     &mut dealer2_signers,
                                                                     "Φ").or(Err(()))?;
            let dealer2_their_encrypted_secret_shares = dealer2_state.their_encrypted_secret_shares()?;

            let mut dealer3_signers: Vec<Participant> = vec!(signer1.clone(), signer2.clone(), signer3.clone());
            let dealer3_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &dealer3_dh_sk,
                                                                     &dealer3.index,
                                                                     &dealer3coeffs,
                                                                     &mut dealer3_signers,
                                                                     "Φ").or(Err(()))?;
            let dealer3_their_encrypted_secret_shares = dealer3_state.their_encrypted_secret_shares()?;

            let mut signer1_dealers: Vec<Participant> = vec!(dealer1.clone(), dealer2.clone(), dealer3.clone());
            let signer1_state = DistributedKeyGeneration::<RoundOne>::new_signer_state(&params,
                                                                     &signer1_dh_sk,
                                                                     &signer1.index,
                                                                     &mut signer1_dealers,
                                                                     "Φ").or(Err(()))?;

            let mut signer2_dealers: Vec<Participant> = vec!(dealer1.clone(), dealer2.clone(), dealer3.clone());
            let signer2_state = DistributedKeyGeneration::<RoundOne>::new_signer_state(&params,
                                                                     &signer2_dh_sk,
                                                                     &signer2.index,
                                                                     &mut signer2_dealers,
                                                                     "Φ").or(Err(()))?;

            let mut signer3_dealers: Vec<Participant> = vec!(dealer1.clone(), dealer2.clone(), dealer3.clone());
            let signer3_state = DistributedKeyGeneration::<RoundOne>::new_signer_state(&params,
                                                                     &signer3_dh_sk,
                                                                     &signer3.index,
                                                                     &mut signer3_dealers,
                                                                     "Φ").or(Err(()))?;

            let signer1_my_encrypted_secret_shares = vec!(dealer1_their_encrypted_secret_shares[0].clone(),
                                                          dealer2_their_encrypted_secret_shares[0].clone(),
                                                          dealer3_their_encrypted_secret_shares[0].clone());
            let signer2_my_encrypted_secret_shares = vec!(dealer1_their_encrypted_secret_shares[1].clone(),
                                                          dealer2_their_encrypted_secret_shares[1].clone(),
                                                          dealer3_their_encrypted_secret_shares[1].clone());
            let signer3_my_encrypted_secret_shares = vec!(dealer1_their_encrypted_secret_shares[2].clone(),
                                                          dealer2_their_encrypted_secret_shares[2].clone(),
                                                          dealer3_their_encrypted_secret_shares[2].clone());

            let signer1_state = signer1_state.to_round_two(signer1_my_encrypted_secret_shares).or(Err(()))?;
            let signer2_state = signer2_state.to_round_two(signer2_my_encrypted_secret_shares).or(Err(()))?;
            let signer3_state = signer3_state.to_round_two(signer3_my_encrypted_secret_shares).or(Err(()))?;

            let (signer1_group_key, signer1_secret_key) = signer1_state.finish(signer1.clone().commitments.unwrap().points).or(Err(()))?;
            let (signer2_group_key, signer2_secret_key) = signer2_state.finish(signer2.clone().commitments.unwrap().points).or(Err(()))?;
            let (signer3_group_key, signer3_secret_key) = signer3_state.finish(signer3.clone().commitments.unwrap().points).or(Err(()))?;

            assert!(signer1_group_key.0.compress() == signer2_group_key.0.compress());
            assert!(signer2_group_key.0.compress() == signer3_group_key.0.compress());

            let mut group_secret_key = Scalar::zero();
            let indices = [1, 2, 3];

            group_secret_key += calculate_lagrange_coefficients(&1, &indices).unwrap()*signer1_secret_key.key;
            group_secret_key += calculate_lagrange_coefficients(&2, &indices).unwrap()*signer2_secret_key.key;
            group_secret_key += calculate_lagrange_coefficients(&3, &indices).unwrap()*signer3_secret_key.key;

            let group_key = &group_secret_key * &RISTRETTO_BASEPOINT_TABLE;

            assert!(signer3_group_key.0.compress() == group_key.compress());

            let mut dealer_group_key = RistrettoPoint::identity();
            let indices = [1, 2, 3];

            dealer_group_key += calculate_lagrange_coefficients(&1, &indices).unwrap()*dealer1.public_key().unwrap();
            dealer_group_key += calculate_lagrange_coefficients(&2, &indices).unwrap()*dealer2.public_key().unwrap();
            dealer_group_key += calculate_lagrange_coefficients(&3, &indices).unwrap()*dealer3.public_key().unwrap();

            assert!(dealer_group_key.compress() == group_key.compress());

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn encrypt_and_decrypt() {
        let mut rng: OsRng = OsRng;

        let original_share = SecretShare { sender_index: 1,
                                           receiver_index: 2,
                                           polynomial_evaluation: Scalar::random(&mut rng)};

        let mut key = [0u8; 32];
        rng.fill(&mut key);

        let encrypted_share = encrypt_share(&original_share, &key);
        let decrypted_share = decrypt_share(&encrypted_share, &key);

        assert!(decrypted_share.is_ok());
        assert!(original_share.polynomial_evaluation == decrypted_share.unwrap().polynomial_evaluation);
    }

    #[test]
    fn keygen_2_out_of_3_with_random_keys() {
        fn do_test() -> Result<(), ()> {
            let params = Parameters { n: 3, t: 2 };

            let (p1, p1coeffs, dh_sk1) = Participant::new_dealer(&params, 1, None, "Φ");
            let (p2, p2coeffs, dh_sk2) = Participant::new_dealer(&params, 2, None, "Φ");
            let (p3, p3coeffs, dh_sk3) = Participant::new_dealer(&params, 3, None, "Φ");

            p1.proof_of_secret_key.as_ref().unwrap().verify(&p1.index, &p1.public_key().unwrap(), "Φ").or(Err(()))?;
            p2.proof_of_secret_key.as_ref().unwrap().verify(&p2.index, &p2.public_key().unwrap(), "Φ").or(Err(()))?;
            p3.proof_of_secret_key.as_ref().unwrap().verify(&p3.index, &p3.public_key().unwrap(), "Φ").or(Err(()))?;

            let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &dh_sk1,
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut p1_other_participants,
                                                                     "Φ").or(Err(()))?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone());
            let p2_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &dh_sk2,
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut p2_other_participants,
                                                                     "Φ").or(Err(()))?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone());
            let  p3_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                      &dh_sk3,
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut p3_other_participants,
                                                                      "Φ").or(Err(()))?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(), // XXX FIXME indexing
                                           p3_their_encrypted_secret_shares[0].clone());
            let p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                           p3_their_encrypted_secret_shares[1].clone());
            let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                           p2_their_encrypted_secret_shares[1].clone());

            let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
            let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares).or(Err(()))?;
            let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

            let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.commitments.unwrap().points).or(Err(()))?;
            let (p2_group_key, _p2_secret_key) = p2_state.finish(p2.commitments.unwrap().points).or(Err(()))?;
            let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.commitments.unwrap().points).or(Err(()))?;

            assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
            assert!(p2_group_key.0.compress() == p3_group_key.0.compress());

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn keygen_verify_complaint() {
        fn do_test() -> Result<(), ()> {
            let params = Parameters { n: 3, t: 2 };

            let (p1, p1coeffs, dh_sk1) = Participant::new_dealer(&params, 1, None, "Φ");
            let (p2, p2coeffs, dh_sk2) = Participant::new_dealer(&params, 2, None, "Φ");
            let (p3, p3coeffs, dh_sk3) = Participant::new_dealer(&params, 3, None, "Φ");

            p1.proof_of_secret_key.as_ref().unwrap().verify(&p1.index, &p1.public_key().unwrap(), "Φ").or(Err(()))?;
            p2.proof_of_secret_key.as_ref().unwrap().verify(&p2.index, &p2.public_key().unwrap(), "Φ").or(Err(()))?;
            p3.proof_of_secret_key.as_ref().unwrap().verify(&p3.index, &p3.public_key().unwrap(), "Φ").or(Err(()))?;

            let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &dh_sk1,
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut p1_other_participants,
                                                                     "Φ").or(Err(()))?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone());
            let p2_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &dh_sk2,
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut p2_other_participants,
                                                                     "Φ").or(Err(()))?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone());
            let  p3_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                      &dh_sk3,
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut p3_other_participants,
                                                                      "Φ").or(Err(()))?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let complaint: Complaint;

            // Wrong decryption from nonce
            {
                let mut wrong_encrypted_secret_share = p1_their_encrypted_secret_shares[0].clone();
                wrong_encrypted_secret_share.nonce = [42; 16];

                let p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(),
                                               p3_their_encrypted_secret_shares[0].clone());
                // Wrong share inserted here!
                let p2_my_encrypted_secret_shares = vec!(wrong_encrypted_secret_share.clone(),
                                               p3_their_encrypted_secret_shares[1].clone());
                let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                               p2_their_encrypted_secret_shares[1].clone());

                let p1_state = p1_state.clone().to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
                let p3_state = p3_state.clone().to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

                let complaints = p2_state.clone().to_round_two(p2_my_encrypted_secret_shares.clone());
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);
                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.clone().commitments.unwrap().points).or(Err(()))?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.clone().commitments.unwrap().points).or(Err(()))?;

                    assert!(p1_group_key.0.compress() == p3_group_key.0.compress());

                    // Copy for next test
                    complaint = complaints[0].clone();
                } else {
                    return Err(())
                }
            }

            // Wrong decryption of polynomial evaluation
            {
                let mut wrong_encrypted_secret_share = p1_their_encrypted_secret_shares[0].clone();
                wrong_encrypted_secret_share.encrypted_polynomial_evaluation = [42; 32];

                let p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(),
                                               p3_their_encrypted_secret_shares[0].clone());
                // Wrong share inserted here!
                let p2_my_encrypted_secret_shares = vec!(wrong_encrypted_secret_share.clone(),
                                               p3_their_encrypted_secret_shares[1].clone());
                let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                               p2_their_encrypted_secret_shares[1].clone());

                let p1_state = p1_state.clone().to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
                let p3_state = p3_state.clone().to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

                let complaints = p2_state.clone().to_round_two(p2_my_encrypted_secret_shares.clone());
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);
                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.clone().commitments.unwrap().points).or(Err(()))?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.clone().commitments.unwrap().points).or(Err(()))?;

                    assert!(p1_group_key.0.compress() == p3_group_key.0.compress());
                } else {
                    return Err(())
                }
            }

            // Wrong encrypted share
            {
                let dh_key = (p1.dh_public_key.0 * dh_sk1.0).compress().to_bytes();
                let wrong_encrypted_secret_share = encrypt_share(
                    &SecretShare {
                        sender_index: 1,
                        receiver_index: 2,
                        polynomial_evaluation: Scalar::from(42u32)
                    },
                    &dh_key
                );

                let p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(),
                                               p3_their_encrypted_secret_shares[0].clone());
                // Wrong share inserted here!
                let p2_my_encrypted_secret_shares = vec!(wrong_encrypted_secret_share.clone(),
                                               p3_their_encrypted_secret_shares[1].clone());
                let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                               p2_their_encrypted_secret_shares[1].clone());

                let p1_state = p1_state.clone().to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
                let p3_state = p3_state.clone().to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

                let complaints = p2_state.clone().to_round_two(p2_my_encrypted_secret_shares.clone());
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);
                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.clone().commitments.unwrap().points).or(Err(()))?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.clone().commitments.unwrap().points).or(Err(()))?;

                    assert!(p1_group_key.0.compress() == p3_group_key.0.compress());
                } else {
                    return Err(())
                }
            }

            // Wrong complaint leads to blaming the complaint maker
            {
                let _p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(),
                                               p3_their_encrypted_secret_shares[0].clone());
                let _p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                               p3_their_encrypted_secret_shares[1].clone());
                let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                               p2_their_encrypted_secret_shares[1].clone());

                let p3_state = p3_state.clone().to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

                let bad_index = p3_state.blame(&p1_their_encrypted_secret_shares[0], &complaint);
                assert!(bad_index == 2);
            }

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn serialisation() {
        fn do_test() -> Result<(), ()> {
            let params = Parameters { n: 3, t: 2 };

            let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, None, "Φ");
            let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, None, "Φ");
            let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, None, "Φ");

            p1.proof_of_secret_key.as_ref().unwrap().verify(&p1.index, &p1.public_key().unwrap(), "Φ").or(Err(()))?;
            p2.proof_of_secret_key.as_ref().unwrap().verify(&p2.index, &p2.public_key().unwrap(), "Φ").or(Err(()))?;
            p3.proof_of_secret_key.as_ref().unwrap().verify(&p3.index, &p3.public_key().unwrap(), "Φ").or(Err(()))?;

            let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &p1_dh_sk,
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut p1_other_participants,
                                                                     "Φ").or(Err(()))?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone());
            let p2_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &p2_dh_sk,
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut p2_other_participants,
                                                                     "Φ").or(Err(()))?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone());
            let  p3_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                      &p3_dh_sk,
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut p3_other_participants,
                                                                      "Φ").or(Err(()))?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            {
                let p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(),
                                               p3_their_encrypted_secret_shares[0].clone());
                let p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                               p3_their_encrypted_secret_shares[1].clone());
                let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                               p2_their_encrypted_secret_shares[1].clone());

                // Check serialisation

                let bytes = p1.to_bytes();
                assert_eq!(p1, Participant::from_bytes(&bytes).unwrap());

                let bytes = p1coeffs.to_bytes();
                let p1coeffs_deserialised = Coefficients::from_bytes(&bytes).unwrap();
                assert_eq!(p1coeffs.0.len(), p1coeffs_deserialised.0.len());
                for i in 0..p1coeffs.0.len() {
                    assert_eq!(p1coeffs.0[i], p1coeffs_deserialised.0[i]);
                }

                /* MUST TEST FOR SERIALISATION
                let bytes = p1_dh_sk.to_bytes();
                assert_eq!(p1_dh_sk, DHPrivateKey::from_bytes(&bytes).unwrap());

                let bytes = p1.proof_of_secret_key.to_bytes();
                assert_eq!(p1.proof_of_secret_key, NizkOfSecretKey::from_bytes(&bytes).unwrap());

                let bytes = p1_state.their_encrypted_secret_shares().unwrap()[0].to_bytes();
                assert_eq!(p1_state.their_encrypted_secret_shares().unwrap()[0], EncryptedSecretShare::from_bytes(&bytes).unwrap());

                let bytes = p1_state.to_bytes();
                assert_eq!(*p1_state.state, *DistributedKeyGeneration::<RoundOne>::from_bytes(&bytes).unwrap().state);
                */

                // Continue KeyGen

                let p1_state = p1_state.clone().to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
                let p2_state = p2_state.clone().to_round_two(p2_my_encrypted_secret_shares).or(Err(()))?;
                let p3_state = p3_state.clone().to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

                let (p1_group_key, _p1_secret_key) = p1_state.clone().finish(p1.clone().commitments.unwrap().points).or(Err(()))?;
                let (p2_group_key, _p2_secret_key) = p2_state.finish(p2.commitments.unwrap().points).or(Err(()))?;
                let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.clone().commitments.unwrap().points).or(Err(()))?;

                assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
                assert!(p2_group_key.0.compress() == p3_group_key.0.compress());

                // Check serialisation

                /* MUST TEST SERIALISATION
                let bytes = p1_secret_key.to_bytes();
                assert_eq!(p1_secret_key, SecretKey::from_bytes(bytes).unwrap());

                let p1_public_key = p1_secret_key.to_public();
                let bytes = p1_public_key.to_bytes();
                assert_eq!(p1_public_key, IndividualPublicKey::from_bytes(bytes).unwrap());

                let bytes = p1_group_key.to_bytes();
                assert_eq!(p1_group_key, GroupKey::from_bytes(bytes).unwrap());

                let bytes = p1_state.to_bytes();
                assert_eq!(*p1_state.state, *DistributedKeyGeneration::<RoundTwo>::from_bytes(&bytes).unwrap().state);
                */
            }

            {
                let wrong_encrypted_secret_share = EncryptedSecretShare {sender_index: 1,
                                                                         receiver_index: 2,
                                                                         nonce: [0; 16],
                                                                         encrypted_polynomial_evaluation: [0; 32]};

                let p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(),
                                               p3_their_encrypted_secret_shares[0].clone());
                let p2_my_encrypted_secret_shares = vec!(wrong_encrypted_secret_share.clone(),
                                               p3_their_encrypted_secret_shares[1].clone());
                let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                               p2_their_encrypted_secret_shares[1].clone());

                let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
                let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

                let complaints = p2_state.to_round_two(p2_my_encrypted_secret_shares);
                assert!(complaints.is_err());
                let complaints = complaints.unwrap_err();
                if let Error::Complaint(complaints) = complaints {
                    assert!(complaints.len() == 1);

                    let bad_index = p3_state.blame(&wrong_encrypted_secret_share, &complaints[0]);

                    assert!(bad_index == 1);

                    let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.clone().commitments.unwrap().points).or(Err(()))?;
                    let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.clone().commitments.unwrap().points).or(Err(()))?;

                    assert!(p1_group_key.0.compress() == p3_group_key.0.compress());

                    // Check serialisation

                    let bytes = complaints[0].proof.to_bytes();
                    assert_eq!(complaints[0].proof, ComplaintProof::from_bytes(&bytes).unwrap());

                    let bytes = complaints[0].to_bytes();
                    assert_eq!(complaints[0], Complaint::from_bytes(&bytes).unwrap());

                    Ok(())
                } else {
                    Err(())
                }
            }
        }

        assert!(do_test().is_ok());
    }

    #[test]
    fn individual_public_key_share() {
        fn do_test() -> Result<(), ()> {
            let params = Parameters { n: 3, t: 2 };

            let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, None, "Φ");
            let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, None, "Φ");
            let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, None, "Φ");

            p1.proof_of_secret_key.as_ref().unwrap().verify(&p1.index, &p1.public_key().unwrap(), "Φ").or(Err(()))?;
            p2.proof_of_secret_key.as_ref().unwrap().verify(&p2.index, &p2.public_key().unwrap(), "Φ").or(Err(()))?;
            p3.proof_of_secret_key.as_ref().unwrap().verify(&p3.index, &p3.public_key().unwrap(), "Φ").or(Err(()))?;

            let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &p1_dh_sk,
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut p1_other_participants,
                                                                     "Φ").or(Err(()))?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone());
            let p2_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                     &p2_dh_sk,
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut p2_other_participants,
                                                                     "Φ").or(Err(()))?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone());
            let  p3_state = DistributedKeyGeneration::<RoundOne>::new_dealer_state(&params,
                                                                      &p3_dh_sk,
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut p3_other_participants,
                                                                      "Φ").or(Err(()))?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(), // XXX FIXME indexing
                                           p3_their_encrypted_secret_shares[0].clone());
            let p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                           p3_their_encrypted_secret_shares[1].clone());
            let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                           p2_their_encrypted_secret_shares[1].clone());

            let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
            let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares).or(Err(()))?;
            let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

            let (p1_group_key, p1_secret_key) = p1_state.finish(p1.clone().commitments.unwrap().points).or(Err(()))?;
            let (p2_group_key, p2_secret_key) = p2_state.finish(p2.clone().commitments.unwrap().points).or(Err(()))?;
            let (p3_group_key, p3_secret_key) = p3_state.finish(p3.clone().commitments.unwrap().points).or(Err(()))?;

            assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
            assert!(p2_group_key.0.compress() == p3_group_key.0.compress());

            // Check the validity of each IndividualPublicKey

            let p1_public_key = p1_secret_key.to_public();
            let p2_public_key = p2_secret_key.to_public();
            let p3_public_key = p3_secret_key.to_public();

            // The order does not matter
            let commitments = [p2.commitments.unwrap(), p3.commitments.unwrap(), p1.commitments.unwrap()];

            assert!(p1_public_key.verify(&commitments).is_ok());
            assert!(p2_public_key.verify(&commitments).is_ok());
            assert!(p3_public_key.verify(&commitments).is_ok());

            assert!(p1_public_key.verify(&commitments[1..]).is_err());

            // Check that the generated IndividualPublicKey from other participants match
            let p1_recovered_public_key = IndividualPublicKey::generate_from_commitments(1, &commitments);
            let p2_recovered_public_key = IndividualPublicKey::generate_from_commitments(2, &commitments);
            let p3_recovered_public_key = IndividualPublicKey::generate_from_commitments(3, &commitments);

            assert_eq!(p1_public_key, p1_recovered_public_key);
            assert_eq!(p2_public_key, p2_recovered_public_key);
            assert_eq!(p3_public_key, p3_recovered_public_key);

            Ok(())
        }
        assert!(do_test().is_ok());
    }
}