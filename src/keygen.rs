// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

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
//! use frost_dalek::DistributedKeyGeneration;
//! use frost_dalek::Parameters;
//! use frost_dalek::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//!
//! # fn do_test() -> Result<(), ()> {
//! // Set up key shares for a threshold signature scheme which needs at least
//! // 2-out-of-3 signers.
//! let params = Parameters { t: 2, n: 3 };
//!
//! // Alice, Bob, and Carol each generate their secret polynomial coefficients
//! // and commitments to them, as well as a zero-knowledge proof of a secret key.
//! let (alice, alice_coeffs) = Participant::new(&params, 1, &RistrettoPoint::identity());
//! let (bob, bob_coeffs) = Participant::new(&params, 2, &RistrettoPoint::identity());
//! let (carol, carol_coeffs) = Participant::new(&params, 3, &RistrettoPoint::identity());
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
//! alice.proof_of_secret_key.verify(&alice.index, &alice.public_key().unwrap())?;
//!
//! // Similarly, Alice and Carol verify Bob's proof:
//! bob.proof_of_secret_key.verify(&bob.index, &bob.public_key().unwrap())?;
//!
//! // And, again, Alice and Bob verify Carol's proof:
//! carol.proof_of_secret_key.verify(&carol.index, &carol.public_key().unwrap())?;
//!
//! // Alice enters round one of the distributed key generation protocol.
//! let mut alice_other_participants: Vec<Participant> = vec!(bob.clone(), carol.clone());
//! let alice_state = DistributedKeyGeneration::<_>::new(&params, &Scalar::one(), &RistrettoPoint::identity(), &alice.index, &alice_coeffs,
//!                                                      &mut alice_other_participants).or(Err(()))?;
//!
//! // Alice then collects the secret shares which they send to the other participants:
//! let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares()?;
//! // send_to_bob(alice_their_encrypted_secret_shares[0]);
//! // send_to_carol(alice_their_encrypted_secret_shares[1]);
//!
//! // Bob enters round one of the distributed key generation protocol.
//! let mut bob_other_participants: Vec<Participant> = vec!(alice.clone(), carol.clone());
//! let bob_state = DistributedKeyGeneration::<_>::new(&params, &Scalar::one(), &RistrettoPoint::identity(), &bob.index, &bob_coeffs,
//!                                                    &mut bob_other_participants).or(Err(()))?;
//!
//! // Bob then collects the secret shares which they send to the other participants:
//! let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares()?;
//! // send_to_alice(bob_their_encrypted_secret_shares[0]);
//! // send_to_carol(bob_their_encrypted_secret_shares[1]);
//!
//! // Carol enters round one of the distributed key generation protocol.
//! let mut carol_other_participants: Vec<Participant> = vec!(alice.clone(), bob.clone());
//! let carol_state = DistributedKeyGeneration::<_>::new(&params, &Scalar::one(), &RistrettoPoint::identity(), &carol.index, &carol_coeffs,
//!                                                      &mut carol_other_participants).or(Err(()))?;
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
//! let (alice_group_key, alice_secret_key) = alice_state.finish(alice.public_key().unwrap())?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish(bob.public_key().unwrap())?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish(carol.public_key().unwrap())?;
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

#[cfg(feature = "std")]
use std::cmp::Ordering;
#[cfg(not(feature = "std"))]
use core::cmp::Ordering;

#[cfg(feature = "alloc")]
use alloc::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use core::convert::TryInto;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;

use rand::rngs::OsRng;
use rand::Rng;

use sha2::Digest;
use sha2::Sha512;

use zeroize::Zeroize;

use crate::nizk::NizkOfSecretKey;
use crate::parameters::Parameters;

use aes::{Aes256, Block};
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, NewBlockCipher,
    generic_array::GenericArray,
    consts::U32,
};

/// A struct for holding a shard of the shared secret, in order to ensure that
/// the shard is overwritten with zeroes when it falls out of scope.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Coefficients(pub(crate) Vec<Scalar>);

/// A commitment to the dealer's secret polynomial coefficients for Feldman's
/// verifiable secret sharing scheme.
#[derive(Clone, Debug)]
pub struct VerifiableSecretSharingCommitment(pub(crate) Vec<RistrettoPoint>);

/// A participant created by a trusted dealer.
///
/// This can be used to create the participants' keys and secret shares without
/// having to do secret sharing or zero-knowledge proofs.  It's mostly provided
/// for testing and debugging purposes, but there is nothing wrong with using it
/// if you have trust in the dealer to not forge rogue signatures.
#[derive(Clone, Debug)]
pub struct DealtParticipant {
    pub(crate) secret_share: SecretShare,
    pub(crate) public_key: IndividualPublicKey,
    pub(crate) group_key: RistrettoPoint,
}

/// A participant in a threshold signing.
#[derive(Clone, Debug)]
pub struct Participant {
    /// The index of this participant, to keep the participants in order.
    pub index: u32,
    /// The public key used to derive symmetric keys for encrypting and 
    /// decrypting shares via DH.
    pub DH_public_key: RistrettoPoint,
    /// A vector of Pedersen commitments to the coefficients of this
    /// participant's private polynomial.
    pub commitments: Vec<RistrettoPoint>,
    /// The zero-knowledge proof of knowledge of the secret key (a.k.a. the
    /// first coefficient in the private polynomial).  It is constructed as a
    /// Schnorr signature using \\( a_{i0} \\) as the signing key.
    pub proof_of_secret_key: NizkOfSecretKey,
}

impl Participant {
    /// Have a trusted dealer generate all participants' key material and
    /// associated commitments for distribution to the participants.
    ///
    /// # Warning
    ///
    /// Each participant MUST verify with all other n-1 participants that the
    /// [`VerifiableSecretSharingCommitment`] given to them by the dealer is
    /// identical.  Otherwise, the participants' secret shares could be formed
    /// with respect to different polynomials and they will fail to create
    /// threshold signatures which validate.
    pub fn dealer(parameters: &Parameters) -> (Vec<DealtParticipant>, VerifiableSecretSharingCommitment) {
        let mut rng: OsRng = OsRng;
        let secret = Scalar::random(&mut rng);

        generate_shares(parameters, secret, rng)
    }

    /// Construct a new participant for the distributed key generation protocol.
    ///
    /// # Inputs
    ///
    /// * The protocol instance [`Parameters`], and
    /// * This participant's `index`.
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
    /// participant's secret polynomial `Coefficients` which must be kept
    /// private.
    pub fn new(parameters: &Parameters, index: u32, DH_public_key: &RistrettoPoint) -> (Self, Coefficients) {
        // Step 1: Every participant P_i samples t random values (a_{i0}, ..., a_{i(t-1)})
        //         uniformly in ZZ_q, and uses these values as coefficients to define a
        //         polynomial f_i(x) = \sum_{j=0}^{t-1} a_{ij} x^{j} of degree t-1 over
        //         ZZ_q.
        let t: usize = parameters.t as usize;
        let mut rng: OsRng = OsRng;
        let mut coefficients: Vec<Scalar> = Vec::with_capacity(t);
        let mut commitments: Vec<RistrettoPoint> = Vec::with_capacity(t);

        for _ in 0..t {
            coefficients.push(Scalar::random(&mut rng));
        }

        let coefficients = Coefficients(coefficients);

        // Step 3: Every participant P_i computes a public commitment
        //         C_i = [\phi_{i0}, ..., \phi_{i(t-1)}], where \phi_{ij} = g^{a_{ij}},
        //         0 ≤ j ≤ t-1.
        for j in 0..t {
            commitments.push(&coefficients.0[j] * &RISTRETTO_BASEPOINT_TABLE);
        }

        // Yes, I know the steps are out of order.  It saves one scalar multiplication.

        // Step 2: Every P_i computes a proof of knowledge to the corresponding secret
        //         a_{i0} by calculating a Schnorr signature \alpha_i = (s, R).  (In
        //         the FROST paper: \alpha_i = (\mu_i, c_i), but we stick with Schnorr's
        //         original notation here.)
        let proof: NizkOfSecretKey = NizkOfSecretKey::prove(&index, &coefficients.0[0], &commitments[0], rng);

        // Step 4: Every participant P_i broadcasts C_i, \alpha_i to all other participants.
        (Participant { index, DH_public_key: *DH_public_key, commitments, proof_of_secret_key: proof }, coefficients)
    }

    /// Retrieve \\( \alpha_{i0} * B \\), where \\( B \\) is the Ristretto basepoint.
    ///
    /// This is used to pass into the final call to `DistributedKeyGeneration::<RoundTwo>.finish()`.
    pub fn public_key(&self) -> Option<&RistrettoPoint> {
        if !self.commitments.is_empty() {
            return Some(&self.commitments[0]);
        }
        None
    }
}

fn generate_shares(parameters: &Parameters, secret: Scalar, mut rng: OsRng) -> (Vec<DealtParticipant>, VerifiableSecretSharingCommitment) {
    let mut participants: Vec<DealtParticipant> = Vec::with_capacity(parameters.n as usize);

    // STEP 1: Every participant P_i samples t random values (a_{i0}, ..., a_{i(t-1)})
    //         uniformly in ZZ_q, and uses these values as coefficients to define a
    //         polynomial f_i(x) = \sum_{j=0}^{t-1} a_{ij} x^{j} of degree t-1 over
    //         ZZ_q.
    let t: usize = parameters.t as usize;
    let mut coefficients: Vec<Scalar> = Vec::with_capacity(t as usize);
    let mut commitment = VerifiableSecretSharingCommitment(Vec::with_capacity(t as usize));

    coefficients.push(secret);
    for _ in 0..t-1 {
        coefficients.push(Scalar::random(&mut rng));
    }

    let coefficients = Coefficients(coefficients);

    // Step 3: Every participant P_i computes a public commitment
    //         C_i = [\phi_{i0}, ..., \phi_{i(t-1)}], where \phi_{ij} = g^{a_{ij}},
    //         0 ≤ j ≤ t-1.
    for j in 0..t {
        commitment.0.push(&coefficients.0[j] * &RISTRETTO_BASEPOINT_TABLE);
    }

    // Generate secret shares here
    let group_key = &RISTRETTO_BASEPOINT_TABLE * &coefficients.0[0];

    // Only one polynomial because dealer, then secret shards are dependent upon index.
    for i in 1..parameters.n + 1 {
        let secret_share = SecretShare::evaluate_polynomial(&i, &coefficients);
        let public_key = IndividualPublicKey {
            index: i,
            share: &RISTRETTO_BASEPOINT_TABLE * &secret_share.polynomial_evaluation,
        };

        participants.push(DealtParticipant { secret_share, public_key, group_key });
    }
    (participants, commitment)
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
#[derive(Clone, Debug)]
struct ActualState {
    /// The parameters for this instantiation of a threshold signature.
    parameters: Parameters,
    /// The DH secret key for deriving a symettric key to encrypt and decrypt
    /// secret shares.
    DH_secret_key: Scalar,
    /// The DH public key for deriving a symettric key to encrypt and decrypt
    /// secret shares.
    DH_public_key: RistrettoPoint,
    /// A vector of tuples containing the index of each participant and that
    /// respective participant's commitments to their private polynomial
    /// coefficients.
    their_commitments: Vec<(u32, VerifiableSecretSharingCommitment)>,
    /// A vector of ECPoints containing the index of each participant and that
    /// respective participant's DH public key.
    their_DH_public_keys: Vec<(u32, RistrettoPoint)>,
    /// A secret share for this participant.
    my_secret_share: SecretShare,
    /// The secret shares this participant has calculated for all the other participants.
    their_secret_shares: Option<Vec<SecretShare>>,
    /// The encrypted secret shares this participant has calculated for all the other participants.
    their_encrypted_secret_shares: Option<Vec<EncryptedSecretShare>>,
    /// The secret shares this participant has received from all the other participants.
    my_secret_shares: Option<Vec<SecretShare>>,
    /// The encrypted secret shares this participant has received from all the other participants.
    my_encrypted_secret_shares: Option<Vec<EncryptedSecretShare>>,
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

fn encrypt_share(my_index: &u32, share: &SecretShare, aes_key: &GenericArray<u8, U32>) -> EncryptedSecretShare {
    let share_bytes = share.polynomial_evaluation.to_bytes();
    let mut high_block = *Block::from_slice(&share_bytes[..16]);
    let mut low_block = *Block::from_slice(&share_bytes[16..]);

    let cipher = Aes256::new(&aes_key);

    cipher.encrypt_block(&mut high_block);
    cipher.encrypt_block(&mut low_block);

    EncryptedSecretShare {
        sender_index: *my_index,
        receiver_index: share.index,
        encrypted_high_block: high_block[..].try_into().unwrap(),
        encrypted_low_block: low_block[..].try_into().unwrap()
    }
}

fn decrypt_share(encrypted_share: &EncryptedSecretShare, aes_key: &GenericArray<u8, U32>) -> Result<SecretShare, ()> {
    let mut high_block = *Block::from_slice(&encrypted_share.encrypted_high_block);
    let mut low_block = *Block::from_slice(&encrypted_share.encrypted_low_block);

    let cipher = Aes256::new(&aes_key);

    cipher.decrypt_block(&mut high_block);
    cipher.decrypt_block(&mut low_block);

    let mut bytes: [u8; 32] = [0; 32];

    bytes[0..16].copy_from_slice(&high_block);
    bytes[16..32].copy_from_slice(&low_block);

    let evaluation = Scalar::from_canonical_bytes(bytes);
    if evaluation.is_none() {return Err(())}

    Ok(SecretShare { index: encrypted_share.receiver_index, 
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
    pub fn new(
        parameters: &Parameters,
        DH_secret_key: &Scalar,
        DH_public_key: &RistrettoPoint,
        my_index: &u32,
        my_coefficients: &Coefficients,
        other_participants: &mut Vec<Participant>,
    ) -> Result<Self, Vec<u32>>
    {
        let mut their_commitments: Vec<(u32, VerifiableSecretSharingCommitment)> = Vec::with_capacity(parameters.t as usize);
        let mut their_DH_public_keys: Vec<(u32, RistrettoPoint)> = Vec::with_capacity(parameters.t as usize);
        let mut misbehaving_participants: Vec<u32> = Vec::new();

        // Bail if we didn't get enough participants.
        if other_participants.len() != parameters.n as usize - 1 {
            return Err(misbehaving_participants);
        }

        // Step 5: Upon receiving C_l, \sigma_l from participants 1 \le l \le n, l \ne i,
        //         participant P_i verifies \sigma_l = (s_l, r_l), by checking:
        //
        //         s_l ?= H(l, \Phi, \phi_{l0}, g^{r_l} \mdot \phi_{l0}^{-s_i})
        for p in other_participants.iter() {
            let public_key = match p.commitments.get(0) {
                Some(key) => key,
                None      => {
                    misbehaving_participants.push(p.index);
                    continue;
                }
            };
            match p.proof_of_secret_key.verify(&p.index, &public_key) {
                Ok(_)  => {
                            their_commitments.push((p.index, VerifiableSecretSharingCommitment(p.commitments.clone())));
                            their_DH_public_keys.push((p.index, p.DH_public_key));
                          },
                Err(_) => misbehaving_participants.push(p.index),
            }
        }

        // [DIFFERENT_TO_PAPER] If any participant was misbehaving, return their indices.
        if !misbehaving_participants.is_empty() {
            return Err(misbehaving_participants);
        }

        // [DIFFERENT_TO_PAPER] We pre-calculate the secret shares from Round 2
        // Step 1 here since it doesn't require additional online activity.
        // RICE-FROST: We also encrypt them into their_encrypted_secret_shares.
        //
        // Round 2
        // Step 1: Each P_i securely sends to each other participant P_l a secret share
        //         (l, f_i(l)) and keeps (i, f_i(i)) for themselves.
        let mut their_secret_shares: Vec<SecretShare> = Vec::with_capacity(parameters.n as usize - 1);
        let mut their_encrypted_secret_shares: Vec<EncryptedSecretShare> = Vec::with_capacity(parameters.n as usize - 1);

        // XXX need a way to index their_secret_shares
        for p in other_participants.iter() {
            let share = SecretShare::evaluate_polynomial(&p.index, my_coefficients);

            let DH_key = (p.DH_public_key * DH_secret_key).compress().to_bytes();
            let DH_key = GenericArray::from_slice(&DH_key);

/*            let share_bytes = share.polynomial_evaluation.to_bytes();
            let mut high_block = *Block::from_slice(&share_bytes[..16]);
            let mut low_block = *Block::from_slice(&share_bytes[16..]);

            let cipher = Aes256::new(&DH_key);

            cipher.encrypt_block(&mut high_block);
            cipher.encrypt_block(&mut low_block);

            let encrypted_share = EncryptedSecretShare {
                index: p.index,
                encrypted_high_block: high_block[..].try_into().unwrap(),
                encrypted_low_block: low_block[..].try_into().unwrap()
            };
*/
            their_encrypted_secret_shares.push(encrypt_share(my_index, &share, DH_key));

            their_secret_shares.push(share);
            

            // println!("Block 1: {:?}", block_high);
        }

        let my_secret_share = SecretShare::evaluate_polynomial(my_index, my_coefficients);
        let state = ActualState {
            parameters: *parameters,
            DH_secret_key: *DH_secret_key,
            DH_public_key: *DH_public_key,
            their_commitments,
            their_DH_public_keys,
            my_secret_share,
            their_secret_shares: Some(their_secret_shares),
            their_encrypted_secret_shares: Some(their_encrypted_secret_shares),
            my_secret_shares: None,
            my_encrypted_secret_shares: None,
        };

        Ok(DistributedKeyGeneration::<RoundOne> {
            state: Box::new(state),
            data: RoundOne {},
        })
    }

    /// Retrieve a secret share for each other participant, to be given to them
    /// at the end of `DistributedKeyGeneration::<RoundOne>`.
    pub fn their_secret_shares(&self) -> Result<&Vec<SecretShare>, ()> {
        self.state.their_secret_shares.as_ref().ok_or(())
    }

    /// Retrieve an encrypted secret share for each other participant, to be given to them
    /// at the end of `DistributedKeyGeneration::<RoundOne>`.
    pub fn their_encrypted_secret_shares(&self) -> Result<&Vec<EncryptedSecretShare>, ()> {
        self.state.their_encrypted_secret_shares.as_ref().ok_or(())
    }

    /// Progress to round two of the DKG protocol once we have sent each share
    /// from `DistributedKeyGeneration::<RoundOne>.their_secret_shares()` to its
    /// respective other participant, and collected our shares from the other
    /// participants in turn.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_round_two(
        mut self,
        my_encrypted_secret_shares: Vec<EncryptedSecretShare>,
    ) -> Result<DistributedKeyGeneration<RoundTwo>, Vec<Complaint>>
    {
        // Zero out the other participants secret shares from memory.
        if self.state.their_secret_shares.is_some() {
            self.state.their_secret_shares.unwrap().zeroize();
            // XXX Does setting this to None always call drop()?
            self.state.their_secret_shares = None;
        }

        // Zero out the other participants encrypted secret shares from memory.
        if self.state.their_encrypted_secret_shares.is_some() {
            self.state.their_encrypted_secret_shares.unwrap().zeroize();
            // XXX Does setting this to None always call drop()?
            self.state.their_encrypted_secret_shares = None;
        }

        // RICE-FROST

        let mut complaints: Vec<Complaint> = Vec::new();
        /*let mut my_encrypted_secret_shares: Vec<EncryptedSecretShare> = Vec::new();*/
        
        if my_encrypted_secret_shares.len() != self.state.parameters.n as usize - 1 {
            return Err(complaints);
        }

        let mut my_secret_shares: Vec<SecretShare> = Vec::new();

        // Step 2.1: Each P_i decrypts their shares with
        //           key k_il = pk_l^sk_i
        for encrypted_share in my_encrypted_secret_shares.iter(){
            for pk in self.state.their_DH_public_keys.iter(){
                if pk.0 == encrypted_share.sender_index {
                    // TODO:
                    // 1) compute decryption key
                    // 2) decrypt encrypted share
                    // 3) push decrypted share into my_secret_shares

                    let DH_key = (pk.1 * self.state.DH_secret_key).compress().to_bytes();
                    let DH_key = GenericArray::from_slice(&DH_key);
                    // let share_bytes = share.polynomial_evaluation.to_bytes();
                    /*let mut high_block = *Block::from_slice(&encrypted_share.encrypted_high_block);
                    let mut low_block = *Block::from_slice(&encrypted_share.encrypted_low_block);

                    let cipher = Aes256::new(&DH_key);

                    cipher.decrypt_block(&mut high_block);
                    cipher.decrypt_block(&mut low_block);

                    let mut bytes: [u8; 32] = [0; 32];

                    bytes[0..16].copy_from_slice(&high_block);
                    bytes[16..32].copy_from_slice(&low_block);
*/


                    /*let encrypted_share = EncryptedSecretShare {
                        index: p.index,
                        encrypted_high_block: high_block[..].try_into().unwrap(),
                        encrypted_low_block: low_block[..].try_into().unwrap()
                    };
*/

                    // Step 2.2: Each share is verified by calculating:
                    //           g^{f_l(i)} ?= \Prod_{k=0}^{t-1} \phi_{lk}^{i^{k} mod q},
                    //           creating a complaint if the check fails.
                    let decrypted_share = decrypt_share(&encrypted_share, &DH_key);
                    let decrypted_share_ref = &decrypted_share;
                    
                    for (index, commitment) in self.state.their_commitments.iter() {
                        if index == &encrypted_share.sender_index {
                            // If the decrypted share is incorrect, P_i builds
                            // a complaint

                            if decrypted_share.is_err() || decrypted_share_ref.as_ref().unwrap().verify(commitment).is_err() {

                                let mut rng: OsRng = OsRng;
                                let r = Scalar::random(&mut rng);

                                let mut h = Sha512::new();
                                h.update(self.state.DH_public_key.compress().to_bytes());
                                h.update(pk.1.compress().to_bytes());
                                h.update(DH_key);

                                let h = Scalar::from_hash(h);

                                complaints.push(Complaint { maker_index: encrypted_share.receiver_index,
                                                            accused_index: pk.0,
                                                            DH_key: *DH_key,
                                                            proof: ComplaintProof { a1: &RISTRETTO_BASEPOINT_TABLE * &r,
                                                                                    a2: pk.1 * r,
                                                                                    z: r + h * self.state.DH_secret_key, }
                                                          });

                                break;
                            }    
                                
                        }
                    }

                    if decrypted_share.is_ok() { my_secret_shares.push(decrypted_share.unwrap()); }
                }
                
            }
        }

        if !complaints.is_empty() {
            return Err(complaints)
        }
        /*for share in my_secret_shares.iter() {
            // XXX TODO implement sorting for SecretShare and also for a new Commitment type
            for (index, commitment) in self.state.their_commitments.iter() {
                if index == &share.index {
                    // If the decrypted share is incorrect, P_i builds
                    // a complaint
                    match share.verify(commitment){
                        Err(_) => {
                            return Err(())
                        },
                        Ok(_) => (),
                    };
                }
            }
        }*/
        self.state.my_secret_shares = Some(my_secret_shares);

        Ok(DistributedKeyGeneration::<RoundTwo> {
            state: self.state,
            data: RoundTwo {},
        })
    }
}

/// A secret share calculated by evaluating a polynomial with secret
/// coefficients for some indeterminant.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct SecretShare {
    /// The participant index that this secret share was calculated for.
    pub index: u32,
    /// The final evaluation of the polynomial for the participant-respective
    /// indeterminant.
    pub(crate) polynomial_evaluation: Scalar,
}

impl SecretShare {
    /// Evaluate the polynomial, `f(x)` for the secret coefficients at the value of `x`.
    //
    // XXX [PAPER] [CFRG] The participant index CANNOT be 0, or the secret share ends up being Scalar::zero().
    pub(crate) fn evaluate_polynomial(index: &u32, coefficients: &Coefficients) -> SecretShare {
        let term: Scalar = (*index).into();
        let mut sum: Scalar = Scalar::zero();

        // Evaluate using Horner's method.
        for (index, coefficient) in coefficients.0.iter().rev().enumerate() {
            // The secret is the constant term in the polynomial
            sum += coefficient;

            if index != (coefficients.0.len() - 1) {
                sum *= term;
            }
        }
        SecretShare { index: *index, polynomial_evaluation: sum }
    }

    /// Verify that this secret share was correctly computed w.r.t. some secret
    /// polynomial coefficients attested to by some `commitment`.
    pub(crate) fn verify(&self, commitment: &VerifiableSecretSharingCommitment) -> Result<(), ()> {
        let lhs = &RISTRETTO_BASEPOINT_TABLE * &self.polynomial_evaluation;
        let term: Scalar = self.index.into();
        let mut rhs: RistrettoPoint = RistrettoPoint::identity();

        for (index, com) in commitment.0.iter().rev().enumerate() {
            rhs += com;

            if index != (commitment.0.len() - 1) {
                rhs *= term;
            }
        }

        match lhs.compress() == rhs.compress() {
            true => Ok(()),
            false => Err(()),
        }
    }
}


/// A secret share encrypted with a participant's public key
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct EncryptedSecretShare {
    /// The index of the share maker.
    pub sender_index: u32,
    /// The participant index that this secret share was calculated for.
    pub receiver_index: u32,
    /// The encrypted polynomial evaluation.
    /// TODO: figure out the right type!
    pub(crate) encrypted_high_block: [u8; 16],
    pub(crate) encrypted_low_block: [u8; 16],
}

/// A proof that a generated complaint is valid. 
#[derive(Debug)]
pub struct ComplaintProof {
    /// a1 = g^r.
    pub a1: RistrettoPoint,
    /// a2 = pk_l^r.
    pub a2: RistrettoPoint,
    /// z = r + H(pk_i, pk_l, k_il).sh_i
    pub z: Scalar,
}

/// A complaint generated when a participant receives a bad share.
#[derive(Debug)]
pub struct Complaint {
    /// The index of the complaint maker.
    pub maker_index: u32,
    /// The index of the alleged misbehaving participant.
    pub accused_index: u32,
    /// The shared DH key.
    pub DH_key: GenericArray<u8, U32>,
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
    ) -> Result<(), ()> {
        let mut h = Sha512::new();
        h.update(pk_i.compress().to_bytes());
        h.update(pk_l.compress().to_bytes());
        h.update(self.DH_key);

        let h = Scalar::from_hash(h);

        if &self.proof.a1 + pk_i * h != &RISTRETTO_BASEPOINT_TABLE * &self.proof.z { return Err(()) }

        if let Some(key_as_point) = CompressedRistretto::from_slice(&self.DH_key).decompress() {
            if &self.proof.a2 + key_as_point * h != pk_l * &self.proof.z { return Err(()) }
        } else {
            return Err(())
        }

        Ok(())
    }
}

/// Every participant can verify a complaint and determine who is the malicious
/// party. The relevant encrypted share is assumed to exist and publicly retrievable
/// by any participant.
/// TODO: What if the indexes in the complaint are wrong?
fn blame(encrypted_share: &EncryptedSecretShare,
         commitment: &VerifiableSecretSharingCommitment, 
         complaint: &Complaint, 
         pk_i: &RistrettoPoint, 
         pk_l: &RistrettoPoint
) -> u32 {

    if complaint.verify(pk_i, pk_l).is_err() { return complaint.maker_index }

    let share = decrypt_share(encrypted_share, &complaint.DH_key);

    if share.is_err() { return complaint.accused_index }

    match share.unwrap().verify(commitment) {
        Ok(()) => return complaint.accused_index,
        Err(()) => return complaint.maker_index,
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
    pub fn finish(mut self, my_commitment: &RistrettoPoint) -> Result<(GroupKey, SecretKey), ()> {
        let secret_key = self.calculate_signing_key()?;
        let group_key = self.calculate_group_key(my_commitment)?;

        self.state.my_secret_share.zeroize();
        self.state.my_secret_shares.zeroize();

        Ok((group_key, secret_key))
    }

    /// Calculate this threshold signing participant's long-lived secret signing
    /// key by summing all of the polynomial evaluations from the other
    /// participants.
    pub(crate) fn calculate_signing_key(&self) -> Result<SecretKey, ()> {
        let my_secret_shares = self.state.my_secret_shares.as_ref().ok_or(())?;
        let mut key = my_secret_shares.iter().map(|x| x.polynomial_evaluation).sum();

        key += self.state.my_secret_share.polynomial_evaluation;

        Ok(SecretKey { index: self.state.my_secret_share.index, key })
    }

    /// Calculate the group public key used for verifying threshold signatures.
    ///
    /// # Returns
    ///
    /// A [`GroupKey`] for the set of participants.
    pub(crate) fn calculate_group_key(&self, my_commitment: &RistrettoPoint) -> Result<GroupKey, ()> {
        let mut keys: Vec<RistrettoPoint> = Vec::with_capacity(self.state.parameters.n as usize);

        for commitment in self.state.their_commitments.iter() {
            match commitment.1.0.get(0) {
                Some(key) => keys.push(*key),
                None => return Err(()),
            }
        }
        keys.push(*my_commitment);

        Ok(GroupKey(keys.iter().sum()))
    }
}

/// A public verification share for a participant.
///
/// Any participant can recalculate the public verification share, which is the
/// public half of a [`SecretKey`], of any other participant in the protocol.
#[derive(Clone, Debug)]
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
    /// * The [`Parameters`] of this threshold signing instance, and
    /// * A vector of `commitments` regarding the secret polynomial
    ///   [`Coefficients`] that this [`IndividualPublicKey`] was generated with.
    ///
    /// # Returns
    ///
    /// A `Result` with either an empty `Ok` or `Err` value, depending on
    /// whether or not the verification was successful.
    #[allow(unused)]
    pub fn verify(
        &self,
        parameters: &Parameters,
        commitments: &[RistrettoPoint],
    ) -> Result<(), ()>
    {
        let rhs = RistrettoPoint::identity();

        for j in 1..parameters.n {
            for k in 0..parameters.t {
                // XXX ah shit we need the incoming commitments to be sorted or have indices
            }
        }
        unimplemented!()
    }
}

/// A secret key, used by one participant in a threshold signature scheme, to sign a message.
#[derive(Debug, Zeroize)]
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
    pub fn from_bytes(bytes: [u8; 32]) -> Result<GroupKey, ()> {
        let point = CompressedRistretto(bytes).decompress().ok_or(())?;

        Ok(GroupKey(point))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::precomputation::generate_commitment_share_lists;

    use crate::signature::{calculate_lagrange_coefficients, compute_message_hash};
    use crate::signature::SignatureAggregator;

    /// Reconstruct the secret from enough (at least the threshold) already-verified shares.
    fn reconstruct_secret(participants: &[&DealtParticipant]) -> Result<Scalar, &'static str> {
        let all_participant_indices: Vec<u32> = participants.iter().map(|p| p.public_key.index).collect();
        let mut secret = Scalar::zero();

        for this_participant in participants {
            let my_coeff = calculate_lagrange_coefficients(&this_participant.public_key.index,
                                                           &all_participant_indices)?;

            secret += my_coeff * this_participant.secret_share.polynomial_evaluation;
        }
        Ok(secret)
    }

    #[test]
    fn nizk_of_secret_key() {
        let params = Parameters { n: 3, t: 2 };
        let (p, _) = Participant::new(&params, 0, &RistrettoPoint::identity());
        let result = p.proof_of_secret_key.verify(&p.index, &p.commitments[0]);

        assert!(result.is_ok());
    }

    #[test]
    fn verify_secret_sharing_from_dealer() {
        let params = Parameters { n: 3, t: 2 };
        let mut rng: OsRng = OsRng;
        let secret = Scalar::random(&mut rng);
        let (participants, _commitment) = generate_shares(&params, secret, rng);

        let mut subset_participants = Vec::new();
        for i in 0..params.t{
            subset_participants.push(&participants[i as usize]);
        }
        let supposed_secret = reconstruct_secret(&subset_participants);
        assert!(secret == supposed_secret.unwrap());
    }

    #[test]
    fn dkg_with_dealer() {
        let params = Parameters { t: 1, n: 2 };
        let (participants, commitment) = Participant::dealer(&params);
        let (_, commitment2) = Participant::dealer(&params);

        // Verify each of the participants' secret shares.
        for p in participants.iter() {
            let result = p.secret_share.verify(&commitment);

            assert!(result.is_ok(), "participant {} failed to receive a valid secret share", p.public_key.index);

            let result = p.secret_share.verify(&commitment2);

            assert!(!result.is_ok(), "Should not validate with invalid commitment");
        }
    }

    #[test]
    fn dkg_with_dealer_and_signing() {
        let params = Parameters { t: 1, n: 2 };
        let (participants, commitment) = Participant::dealer(&params);

        // Verify each of the participants' secret shares.
        for p in participants.iter() {
            let result = p.secret_share.verify(&commitment);

            assert!(result.is_ok(), "participant {} failed to receive a valid secret share", p.public_key.index);
        }

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p2_public_comshares, mut p2_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);

        let p1_sk = SecretKey {
            index: participants[0].secret_share.index,
            key: participants[0].secret_share.polynomial_evaluation,
        };
        let p2_sk = SecretKey {
            index: participants[1].secret_share.index,
            key: participants[1].secret_share.polynomial_evaluation,
        };

        let group_key = GroupKey(participants[0].group_key);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();
        let p2_partial = p2_sk.sign(&message_hash, &group_key, &mut p2_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();

        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("{:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn secret_share_from_one_coefficients() {
        let mut coeffs: Vec<Scalar> = Vec::new();

        for _ in 0..5 {
            coeffs.push(Scalar::one());
        }

        let coefficients = Coefficients(coeffs);
        let share = SecretShare::evaluate_polynomial(&1, &coefficients);

        assert!(share.polynomial_evaluation == Scalar::from(5u8));

        let mut commitments = VerifiableSecretSharingCommitment(Vec::new());

        for i in 0..5 {
            commitments.0.push(&RISTRETTO_BASEPOINT_TABLE * &coefficients.0[i]);
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
        let share = SecretShare::evaluate_polynomial(&0, &coefficients);

        assert!(share.polynomial_evaluation == Scalar::one());

        let mut commitments = VerifiableSecretSharingCommitment(Vec::new());

        for i in 0..5 {
            commitments.0.push(&RISTRETTO_BASEPOINT_TABLE * &coefficients.0[i]);
        }

        assert!(share.verify(&commitments).is_ok());
    }

    #[test]
    fn single_party_keygen() {
        let params = Parameters { n: 1, t: 1 };

        let (p1, p1coeffs) = Participant::new(&params, 1, &RistrettoPoint::identity());

        p1.proof_of_secret_key.verify(&p1.index, &p1.commitments[0]).unwrap();

        let mut p1_other_participants: Vec<Participant> = Vec::new();
        let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &Scalar::one(),
                                                                 &RistrettoPoint::identity(),
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut p1_other_participants).unwrap();
        let p1_my_encrypted_secret_shares = Vec::new();
        let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).unwrap();
        let result = p1_state.finish(p1.public_key().unwrap());

        assert!(result.is_ok());

        let (p1_group_key, p1_secret_key) = result.unwrap();

        assert!(p1_group_key.0.compress() == (&p1_secret_key.key * &RISTRETTO_BASEPOINT_TABLE).compress());
    }

    #[test]
    fn keygen_3_out_of_5() {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs) = Participant::new(&params, 1, &RistrettoPoint::identity());
        let (p2, p2coeffs) = Participant::new(&params, 2, &RistrettoPoint::identity());
        let (p3, p3coeffs) = Participant::new(&params, 3, &RistrettoPoint::identity());
        let (p4, p4coeffs) = Participant::new(&params, 4, &RistrettoPoint::identity());
        let (p5, p5coeffs) = Participant::new(&params, 5, &RistrettoPoint::identity());

        p1.proof_of_secret_key.verify(&p1.index, &p1.public_key().unwrap()).unwrap();
        p2.proof_of_secret_key.verify(&p2.index, &p2.public_key().unwrap()).unwrap();
        p3.proof_of_secret_key.verify(&p3.index, &p3.public_key().unwrap()).unwrap();
        p4.proof_of_secret_key.verify(&p4.index, &p4.public_key().unwrap()).unwrap();
        p5.proof_of_secret_key.verify(&p5.index, &p5.public_key().unwrap()).unwrap();

        let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &Scalar::one(),
                                                                 &RistrettoPoint::identity(),
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut p1_other_participants).unwrap();
        let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap();

        let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone(), p4.clone(), p5.clone());
        let p2_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &Scalar::one(),
                                                                 &RistrettoPoint::identity(),
                                                                 &p2.index,
                                                                 &p2coeffs,
                                                                 &mut p2_other_participants).unwrap();
        let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

        let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p4.clone(), p5.clone());
        let  p3_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                  &Scalar::one(),
                                                                  &RistrettoPoint::identity(),
                                                                  &p3.index,
                                                                  &p3coeffs,
                                                                  &mut p3_other_participants).unwrap();
        let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares().unwrap();

        let mut p4_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p5.clone());
        let p4_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &Scalar::one(),
                                                                 &RistrettoPoint::identity(),
                                                                 &p4.index,
                                                                 &p4coeffs,
                                                                 &mut p4_other_participants).unwrap();
        let p4_their_encrypted_secret_shares = p4_state.their_encrypted_secret_shares().unwrap();

        let mut p5_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone());
        let p5_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                 &Scalar::one(),
                                                                 &RistrettoPoint::identity(),
                                                                 &p5.index,
                                                                 &p5coeffs,
                                                                 &mut p5_other_participants).unwrap();
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

        let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.public_key().unwrap()).unwrap();
        let (p2_group_key, _p2_secret_key) = p2_state.finish(p2.public_key().unwrap()).unwrap();
        let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.public_key().unwrap()).unwrap();
        let (p4_group_key, _p4_secret_key) = p4_state.finish(p4.public_key().unwrap()).unwrap();
        let (p5_group_key, _p5_secret_key) = p5_state.finish(p5.public_key().unwrap()).unwrap();

        assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
        assert!(p2_group_key.0.compress() == p3_group_key.0.compress());
        assert!(p3_group_key.0.compress() == p4_group_key.0.compress());
        assert!(p4_group_key.0.compress() == p5_group_key.0.compress());

        assert!(p5_group_key.0.compress() ==
                (p1.public_key().unwrap() +
                 p2.public_key().unwrap() +
                 p3.public_key().unwrap() +
                 p4.public_key().unwrap() +
                 p5.public_key().unwrap()).compress());
    }


    #[test]
    fn keygen_2_out_of_3() {
        fn do_test() -> Result<(), ()> {
            let params = Parameters { n: 3, t: 2 };

            let (p1, p1coeffs) = Participant::new(&params, 1, &RistrettoPoint::identity());
            let (p2, p2coeffs) = Participant::new(&params, 2, &RistrettoPoint::identity());
            let (p3, p3coeffs) = Participant::new(&params, 3, &RistrettoPoint::identity());

            p1.proof_of_secret_key.verify(&p1.index, &p1.public_key().unwrap())?;
            p2.proof_of_secret_key.verify(&p2.index, &p2.public_key().unwrap())?;
            p3.proof_of_secret_key.verify(&p3.index, &p3.public_key().unwrap())?;

            let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &Scalar::one(),
                                                                     &RistrettoPoint::identity(),
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut p1_other_participants).or(Err(()))?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone());
            let p2_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &Scalar::one(),
                                                                     &RistrettoPoint::identity(),
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut p2_other_participants).or(Err(()))?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone());
            let  p3_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                      &Scalar::one(),
                                                                      &RistrettoPoint::identity(),
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut p3_other_participants).or(Err(()))?;
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

            let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.public_key().unwrap())?;
            let (p2_group_key, _p2_secret_key) = p2_state.finish(p2.public_key().unwrap())?;
            let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.public_key().unwrap())?;

            assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
            assert!(p2_group_key.0.compress() == p3_group_key.0.compress());

            Ok(())
        }
        assert!(do_test().is_ok());
    }

    #[test]
    fn encrypt_and_decrypt() {

        let mut rng: OsRng = OsRng;

        let original_share = SecretShare { index: 2,
                                           polynomial_evaluation: Scalar::random(&mut rng)};


        let mut random_bytes = [0u8; 32];
        rng.fill(&mut random_bytes);

        let key = GenericArray::from_slice(&random_bytes);

        let index = 1;

        let encrypted_share = encrypt_share(&index, &original_share, &key);
        let decrypted_share = decrypt_share(&encrypted_share, &key);

        assert!(decrypted_share.is_ok());
        assert!(original_share.polynomial_evaluation == decrypted_share.unwrap().polynomial_evaluation);
    }

    #[test]
    fn keygen_2_out_of_3_with_random_keys() {
        fn do_test() -> Result<(), ()> {
            let params = Parameters { n: 3, t: 2 };

            let mut rng: OsRng = OsRng;

            let dh_sk1 = Scalar::random(&mut rng);
            let dh_pk1 = &RISTRETTO_BASEPOINT_TABLE * &dh_sk1;
            let (p1, p1coeffs) = Participant::new(&params, 1, &dh_pk1);

            let dh_sk2 = Scalar::random(&mut rng);
            let dh_pk2 = &RISTRETTO_BASEPOINT_TABLE * &dh_sk2;
            let (p2, p2coeffs) = Participant::new(&params, 2, &dh_pk2);

            let dh_sk3 = Scalar::random(&mut rng);
            let dh_pk3 = &RISTRETTO_BASEPOINT_TABLE * &dh_sk3;
            let (p3, p3coeffs) = Participant::new(&params, 3, &dh_pk3);

            p1.proof_of_secret_key.verify(&p1.index, &p1.public_key().unwrap())?;
            p2.proof_of_secret_key.verify(&p2.index, &p2.public_key().unwrap())?;
            p3.proof_of_secret_key.verify(&p3.index, &p3.public_key().unwrap())?;

            let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &dh_sk1,
                                                                     &dh_pk1,
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut p1_other_participants).or(Err(()))?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone());
            let p2_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &dh_sk2,
                                                                     &dh_pk2,
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut p2_other_participants).or(Err(()))?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone());
            let  p3_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                      &dh_sk3,
                                                                      &dh_pk3,
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut p3_other_participants).or(Err(()))?;
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

            let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.public_key().unwrap())?;
            let (p2_group_key, _p2_secret_key) = p2_state.finish(p2.public_key().unwrap())?;
            let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.public_key().unwrap())?;

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

            let mut rng: OsRng = OsRng;

            let dh_sk1 = Scalar::random(&mut rng);
            let dh_pk1 = &RISTRETTO_BASEPOINT_TABLE * &dh_sk1;
            let (p1, p1coeffs) = Participant::new(&params, 1, &dh_pk1);

            let dh_sk2 = Scalar::random(&mut rng);
            let dh_pk2 = &RISTRETTO_BASEPOINT_TABLE * &dh_sk2;
            let (p2, p2coeffs) = Participant::new(&params, 2, &dh_pk2);

            let dh_sk3 = Scalar::random(&mut rng);
            let dh_pk3 = &RISTRETTO_BASEPOINT_TABLE * &dh_sk3;
            let (p3, p3coeffs) = Participant::new(&params, 3, &dh_pk3);

            p1.proof_of_secret_key.verify(&p1.index, &p1.public_key().unwrap())?;
            p2.proof_of_secret_key.verify(&p2.index, &p2.public_key().unwrap())?;
            p3.proof_of_secret_key.verify(&p3.index, &p3.public_key().unwrap())?;

            let mut p1_other_participants: Vec<Participant> = vec!(p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &dh_sk1,
                                                                     &dh_pk1,
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut p1_other_participants).or(Err(()))?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let mut p2_other_participants: Vec<Participant> = vec!(p1.clone(), p3.clone());
            let p2_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &dh_sk2,
                                                                     &dh_pk2,
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut p2_other_participants).or(Err(()))?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let mut p3_other_participants: Vec<Participant> = vec!(p1.clone(), p2.clone());
            let  p3_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                      &dh_sk3,
                                                                      &dh_pk3,
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut p3_other_participants).or(Err(()))?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let wrong_encrypted_secret_share = EncryptedSecretShare { sender_index: 1,
                                                             receiver_index: 2,
                                                             encrypted_high_block: [0; 16],
                                                             encrypted_low_block: [1; 16]
            };

            let p1_my_encrypted_secret_shares = vec!(p2_their_encrypted_secret_shares[0].clone(), // XXX FIXME indexing
                                           p3_their_encrypted_secret_shares[0].clone());
            // Wrong share inserted here!
            let p2_my_encrypted_secret_shares = vec!(wrong_encrypted_secret_share.clone(),
                                           p3_their_encrypted_secret_shares[1].clone());
            let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                           p2_their_encrypted_secret_shares[1].clone());

            let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
            let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;


            let complaints = p2_state.to_round_two(p2_my_encrypted_secret_shares);
            assert!(complaints.is_err());
            let complaints = complaints.unwrap_err();
            assert!(complaints.len() == 1);

            let bad_index = blame(&wrong_encrypted_secret_share, &p3_state.state.their_commitments[0].1, &complaints[0], &dh_pk2, &dh_pk1);
            assert!(bad_index == 1);

            let (p1_group_key, _p1_secret_key) = p1_state.finish(p1.public_key().unwrap())?;
            let (p3_group_key, _p3_secret_key) = p3_state.finish(p3.public_key().unwrap())?;

            assert!(p1_group_key.0.compress() == p3_group_key.0.compress());

            Ok(())
        }
        assert!(do_test().is_ok());
    }

}