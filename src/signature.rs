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

//! FROST signatures and their creation.

#[cfg(feature = "std")]
use std::boxed::Box;
#[cfg(feature = "alloc")]
use alloc::boxed::Box;

use core::cmp::Ordering;
use core::convert::TryInto;

#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "alloc")]
use alloc::collections::BTreeMap;
#[cfg(feature = "std")]
use std::collections::btree_map::Values;
#[cfg(feature = "alloc")]
use alloc::collections::btree_map::Values;

#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;

use sha2::Digest;
use sha2::Sha512;

use crate::keygen::Error;
use crate::keygen::GroupKey;
use crate::keygen::IndividualPublicKey;
use crate::parameters::Parameters;
use crate::precomputation::SecretCommitmentShareList;

pub use crate::keygen::SecretKey;

// XXX Nonce reuse is catastrophic and results in obtaining an individual
//     signer's long-term secret key; it must be prevented at all costs.

/// An individual signer in the threshold signature scheme.
#[derive(Clone, Copy, Debug, Eq)]
pub struct Signer {
    /// The participant index of this signer.
    pub participant_index: u32,
    /// One of the commitments that were published by each signing participant
    /// in the pre-computation phase.
    pub published_commitment_share: (RistrettoPoint, RistrettoPoint),
}

impl Ord for Signer {
    fn cmp(&self, other: &Signer) -> Ordering {
        self.partial_cmp(other).unwrap()
    }
}

impl PartialOrd for Signer {
    fn partial_cmp(&self, other: &Signer) -> Option<Ordering> {
        match self.participant_index.cmp(&other.participant_index) {
            Ordering::Less => Some(Ordering::Less),
            // WARNING: Participants cannot have identical indices, so dedup() MUST be called.
            Ordering::Equal => Some(Ordering::Equal),
            Ordering::Greater => Some(Ordering::Greater),
        }
    }
}

impl PartialEq for Signer {
    fn eq(&self, other: &Signer) -> bool {
        self.participant_index == other.participant_index
    }
}

/// A partially-constructed threshold signature, made by each participant in the
/// signing protocol during the first phase of a signature creation.
#[derive(Debug, Eq, PartialEq)]
pub struct PartialThresholdSignature {
    pub(crate) index: u32,
    pub(crate) z: Scalar,
}

impl PartialThresholdSignature {
    /// Serialize this partial threshold signature to an array of 36 bytes.
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut bytes = [0u8; 36];

        bytes[..4].copy_from_slice(&self.index.to_le_bytes());
        bytes[4..].copy_from_slice(self.z.as_bytes());

        bytes
    }

    /// Attempt to deserialize a partial threshold signature from an array of 36 bytes.
    pub fn from_bytes(bytes: [u8; 36]) -> Result<PartialThresholdSignature, Error> {
        let index = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?
        );

        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes[4..36]);
        let z = Scalar::from_canonical_bytes(array).ok_or(Error::SerialisationError)?;

        Ok(PartialThresholdSignature { index, z })
    }
}

/// A complete, aggregated threshold signature.
#[derive(Debug, Eq, PartialEq)]
pub struct ThresholdSignature {
    pub(crate) R: RistrettoPoint,
    pub(crate) z: Scalar,
}

impl ThresholdSignature {
    /// Serialize this threshold signature to an array of 64 bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];

        bytes[..32].copy_from_slice(&self.R.compress().as_bytes()[..]);
        bytes[32..].copy_from_slice(&self.z.as_bytes()[..]);
        bytes
    }

    /// Attempt to deserialize a threshold signature from an array of 64 bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Result<ThresholdSignature, Error> {
        let mut array = [0u8; 32];

        array.copy_from_slice(&bytes[..32]);

        let R = CompressedRistretto(array).decompress().ok_or(Error::SerialisationError)?;

        array.copy_from_slice(&bytes[32..]);

        let z = Scalar::from_canonical_bytes(array).ok_or(Error::SerialisationError)?;

        Ok(ThresholdSignature { R, z })
    }
}

macro_rules! impl_indexed_hashmap {
    (Type = $type:ident, Item = $item:ident) => {

impl $type {
    pub(crate) fn new() -> $type {
        $type(BTreeMap::new())
    }

    // [CFRG] Since the sorting order matters for the public API, both it
    // and the canonicalisation of the participant indices needs to be
    // specified.
    pub(crate) fn insert(&mut self, index: &u32, point: $item) {
        self.0.insert(index.to_be_bytes(), point);
    }

    pub(crate) fn get(&self, index: &u32) -> Option<&$item> {
        self.0.get(&index.to_be_bytes())
    }

    #[allow(unused)]
    pub(crate) fn sorted(&self) -> Vec<(u32, $item)> {
        let mut sorted: Vec<(u32, $item)> = Vec::with_capacity(self.0.len());

        for (i, point) in self.0.iter() {
            let index = u32::from_be_bytes(*i);
            sorted.insert(index as usize, (index, *point));
        }
        sorted
    }

    #[allow(unused)]
    pub(crate) fn values(&self) -> Values<'_, [u8; 4], $item> {
        self.0.values()
    }
}

}} // END macro_rules! impl_indexed_hashmap

/// A struct for storing signers' R values with the signer's participant index.
//
// I hate this so much.
//
// XXX TODO there might be a more efficient way to optimise this data structure
//     and its algorithms?
#[derive(Debug)]
struct SignerRs(pub(crate) BTreeMap<[u8; 4], RistrettoPoint>);

impl_indexed_hashmap!(Type = SignerRs, Item = RistrettoPoint);

/// A type for storing signers' partial threshold signatures along with the
/// respective signer participant index.
#[derive(Debug)]
pub(crate) struct PartialThresholdSignatures(pub(crate) BTreeMap<[u8; 4], Scalar>);

impl_indexed_hashmap!(Type = PartialThresholdSignatures, Item = Scalar);

/// A type for storing signers' individual public keys along with the respective
/// signer participant index.
#[derive(Debug)]
pub(crate) struct IndividualPublicKeys(pub(crate) BTreeMap<[u8; 4], RistrettoPoint>);

impl_indexed_hashmap!(Type = IndividualPublicKeys, Item = RistrettoPoint);

/// Compute a Sha-512 hash of a `context_string` and a `message`.
pub fn compute_message_hash(context_string: &[u8], message: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();

    h.update(context_string);
    h.update(message);

    let mut output = [0u8; 64];

    output.copy_from_slice(h.finalize().as_slice());
    output
}

fn compute_binding_factors_and_group_commitment(
    message_hash: &[u8; 64],
    signers: &[Signer],
) -> (BTreeMap<u32, Scalar>, SignerRs)
{
	let mut binding_factors: BTreeMap<u32, Scalar> = BTreeMap::new();
    let mut Rs: SignerRs = SignerRs::new();

    // [CFRG] Should the hash function be hardcoded in the RFC or should
    // we instead specify the output/block size?
    let mut h = Sha512::new();

    // [DIFFERENT_TO_PAPER] I added a context string and reordered to hash
    // constants like the message first.
    h.update(b"FROST-SHA512");
    h.update(&message_hash[..]);

    // [DIFFERENT_TO_PAPER] I added the set of participants (in the paper
    // B = <(i, D_{ij}, E_(ij))> i \E S) here to avoid rehashing them over and
    // over again.
    for signer in signers.iter() {
        let hiding = signer.published_commitment_share.0;
        let binding = signer.published_commitment_share.1;

        h.update(signer.participant_index.to_be_bytes());
        h.update(hiding.compress().as_bytes());
        h.update(binding.compress().as_bytes());
    }

    for signer in signers.iter() {
        let hiding = signer.published_commitment_share.0;
        let binding = signer.published_commitment_share.1;

        let mut h1 = h.clone();

        // [DIFFERENT_TO_PAPER] I put in the participant index last to finish
        // their unique calculation of rho.
        h1.update(signer.participant_index.to_be_bytes());
        h1.update(hiding.compress().as_bytes());
        h1.update(binding.compress().as_bytes());

        let binding_factor = Scalar::from_hash(h1); // This is rho in the paper.

        // THIS IS THE MAGIC STUFF ↓↓↓
        Rs.insert(&signer.participant_index, hiding + (binding_factor * binding));
	    binding_factors.insert(signer.participant_index, binding_factor);
    }
    (binding_factors, Rs)
}

fn compute_challenge(message_hash: &[u8; 64], group_key: &GroupKey, R: &RistrettoPoint) -> Scalar {
    let mut h2 = Sha512::new();

    // XXX [PAPER] Decide if we want a context string for the challenge.  This
    // would break compatibility with standard ed25519 libraries for verification.
    h2.update(b"FROST-SHA512");
    h2.update(R.compress().as_bytes());
    h2.update(group_key.to_bytes());
    h2.update(&message_hash[..]);

    Scalar::from_hash(h2)
}

/// Calculate using Lagrange's method the interpolation of a polynomial.
///
/// # Note
///
/// isis stole this from Chelsea and Ian but they stole it from Lagrange, so who
/// can really say.
pub(crate) fn calculate_lagrange_coefficients(
    participant_index: &u32,
    all_participant_indices: &[u32],
) -> Result<Scalar, &'static str>
{
    let mut num = Scalar::one();
    let mut den = Scalar::one();

    let mine = Scalar::from(*participant_index);

    for j in all_participant_indices.iter() {
        if j == participant_index {
            continue;
        }
        let s = Scalar::from(*j);

        num *= s;
        den *= s - mine; // Check to ensure that one person isn't trying to sign twice.
    }

    if den == Scalar::zero() {
        return Err("Duplicate shares provided");
    }
    Ok(num * den.invert())
}

impl SecretKey {
    /// Compute an individual signer's [`PartialThresholdSignature`] contribution to
    /// a [`ThresholdSignature`] on a `message`.
    ///
    /// # Inputs
    ///
    /// * The `message_hash` to be signed by every individual signer, this should be
    ///   the `Sha512` digest of the message, optionally along with some application-specific
    ///   context string, and can be calculated with the helper function
    ///   [`compute_message_hash`].
    /// * The public [`GroupKey`] for this group of signing participants,
    /// * This signer's [`SecretCommitmentShareList`] being used in this instantiation and
    /// * The index of the particular `CommitmentShare` being used, and
    /// * The list of all the currently participating [`Signer`]s (including ourself).
    ///
    /// # Warning
    ///
    /// The secret share `index` here **must** be the same secret share
    /// corresponding to its public commitment which is passed to
    /// `SignatureAggregrator.include_signer()`.
    ///
    /// # Returns
    ///
    /// A Result whose `Ok` value contains a [`PartialThresholdSignature`], which
    /// should be sent to the [`SignatureAggregator`].  Otherwise, its `Err` value contains
    /// a string describing the error which occurred.
    pub fn sign(
        &self,
        message_hash: &[u8; 64],
        group_key: &GroupKey,
        // XXX [PAPER] I don't know that we can guarantee simultaneous runs of the protocol
        // with these nonces being potentially reused?
        my_secret_commitment_share_list: &mut SecretCommitmentShareList,
        my_commitment_share_index: usize,
        signers: &[Signer],
    ) -> Result<PartialThresholdSignature, &'static str>
    {
        if my_commitment_share_index + 1 > my_secret_commitment_share_list.commitments.len() {
            return Err("Commitment share index out of bounds");
        }

        let (binding_factors, Rs) = compute_binding_factors_and_group_commitment(&message_hash, &signers);
        let R: RistrettoPoint = Rs.values().sum();
        let challenge = compute_challenge(&message_hash, &group_key, &R);
        let my_binding_factor = binding_factors.get(&self.index).ok_or("Could not compute our blinding factor")?;
        let all_participant_indices: Vec<u32> = signers.iter().map(|x| x.participant_index).collect();
        let lambda: Scalar = calculate_lagrange_coefficients(&self.index, &all_participant_indices)?;
        let my_commitment_share = my_secret_commitment_share_list.commitments[my_commitment_share_index].clone();
        let z = my_commitment_share.hiding.nonce +
            (my_commitment_share.binding.nonce * my_binding_factor) +
            (lambda * self.key * challenge);

        // [DIFFERENT_TO_PAPER] We need to instead pass in the commitment
        // share list and zero-out the used commitment share, which means the
        // signature aggregator needs to tell us somehow which one they picked from
        // our published list.
        //
        // I.... don't really love this API?

        // XXX [PAPER] If we do lists like this, then the indices of the public
        // commitment shares go out of sync.

        // Zero out our secrets from memory to prevent nonce reuse.
        my_secret_commitment_share_list.drop_share(my_commitment_share);

        Ok(PartialThresholdSignature { index: self.index, z })
    }
}

/// A signature aggregator, in any of various states.
pub trait Aggregator {}

/// The internal state of a signature aggregator.
#[derive(Debug)]
pub(crate) struct AggregatorState {
    /// The protocol instance parameters.
    pub(crate) parameters: Parameters,
    /// The set of signing participants for this round.
    pub(crate) signers: Vec<Signer>,
    /// The signer's public keys for verifying their [`PartialThresholdSignature`].
    pub(crate) public_keys: IndividualPublicKeys,
    /// The partial signatures from individual participants which have been
    /// collected thus far.
    pub(crate) partial_signatures: PartialThresholdSignatures,
    /// The group public key for all the participants.
    pub(crate) group_key: GroupKey,
}

/// A signature aggregator is an untrusted party who coalesces all of the
/// participating signers' published commitment shares and their
/// [`PartialThresholdSignature`] and creates the final [`ThresholdSignature`].
/// The signature aggregator may even be one of the \\(t\\) participants in this
/// signing operation.
#[derive(Debug)]
pub struct SignatureAggregator<A: Aggregator> {
    /// The aggregator's actual state, shared across types.
    pub(crate) state: Box<AggregatorState>,
    /// The aggregator's additional state.
    pub(crate) aggregator: A,
}

/// The initial state for a [`SignatureAggregator`], which may include invalid
/// or non-sensical data.
#[derive(Debug)]
pub struct Initial<'sa> {
    /// An optional context string for computing the message hash.
    pub(crate) context: &'sa [u8],
    /// The message to be signed.
    pub(crate) message: &'sa [u8],
}

impl Aggregator for Initial<'_> {}

/// The finalized state for a [`SignatureAggregator`], which has thoroughly
/// validated its data.
///
/// # Guarantees
///
/// * There are no duplicate signing attempts from the same individual signer.
/// * All expected signers have contributed a partial signature.
/// * All expected signers have a public key.
// XXX Should we check that these public keys are valid?
///
/// This leaves only one remaining failure mode for the actual aggregation of
/// the partial signatures:
///
/// * Any signer could have contributed a malformed partial signature.
#[derive(Debug)]
pub struct Finalized {
    /// The hashed context and message for signing.
    pub(crate) message_hash: [u8; 64],
}

impl Aggregator for Finalized {}

impl SignatureAggregator<Initial<'_>> {
    /// Construct a new signature aggregator from some protocol instantiation
    /// `parameters` and a `message` to be signed.
    ///
    /// # Inputs
    ///
    /// * The [`Parameters`] for this threshold signing operation,
    /// * The public [`GroupKey`] for the intended sets of signers,
    /// * An optional `context` string for computing the message hash,
    /// * The `message` to be signed.
    ///
    /// # Notes
    ///
    /// The `context` and the `message` string should be given to the aggregator
    /// so that all signers can query them before deciding whether or not to
    /// sign.
    ///
    /// # Returns
    ///
    /// A new [`SignatureAggregator`].
    pub fn new<'sa>(
        parameters: Parameters,
        group_key: GroupKey,
        context: &'sa [u8],
        message: &'sa [u8],
    ) -> SignatureAggregator<Initial<'sa>> {
        let signers: Vec<Signer> = Vec::with_capacity(parameters.t as usize);
        let public_keys = IndividualPublicKeys::new();
        let partial_signatures = PartialThresholdSignatures::new();
        let state = AggregatorState { parameters, signers, public_keys, partial_signatures, group_key };

        SignatureAggregator { state: Box::new(state), aggregator: Initial { context, message } }
    }

    /// Include a signer in the protocol.
    ///
    /// # Warning
    ///
    /// If this method is called for a specific participant, then that
    /// participant MUST provide a partial signature to give to
    /// [`SignatureAggregator.include_partial_signature`], otherwise the signing
    /// procedure will fail.
    ///
    /// # Panics
    ///
    /// If the `signer.participant_index` doesn't match the `public_key.index`.
    pub fn include_signer(
        &mut self,
        participant_index: u32,
        published_commitment_share: (RistrettoPoint, RistrettoPoint),
        public_key: IndividualPublicKey)
    {
        assert_eq!(participant_index, public_key.index,
                   "Tried to add signer with participant index {}, but public key is for participant with index {}",
                   participant_index, public_key.index);

        self.state.signers.push(Signer { participant_index, published_commitment_share });
        self.state.public_keys.insert(&public_key.index, public_key.share);
    }

    /// Get the list of partipating signers.
    ///
    /// # Returns
    ///
    /// A `&Vec<Signer>` of the participating signers in this round.
    pub fn get_signers<'sa>(&'sa mut self) -> &'sa Vec<Signer> {
        // .sort() must be called before .dedup() because the latter only
        // removes consecutive repeated elements.
        self.state.signers.sort();
        self.state.signers.dedup();

        &self.state.signers
    }

    /// Helper function to get the remaining signers who were expected to sign,
    /// but have not yet contributed their [`PartialThresholdSignature`]s.
    ///
    /// This can be used by an honest aggregator who wishes to ensure that the
    /// aggregation procedure is ready to be run, or who wishes to be able to
    /// remind/poll individual signers for their [`PartialThresholdSignature`]
    /// contribution.
    ///
    /// # Returns
    ///
    /// A sorted `Vec` of unique [`Signer`]s who have yet to contribute their
    /// partial signatures.
    pub fn get_remaining_signers(&self) -> Vec<Signer> {
        let mut remaining_signers: Vec<Signer> = Vec::new();

        for signer in self.state.signers.iter() {
            if self.state.partial_signatures.get(&signer.participant_index).is_none() {
                remaining_signers.push(*signer);
            }
        }
        remaining_signers.sort();
        remaining_signers.dedup();
        remaining_signers
    }

    /// Add a [`PartialThresholdSignature`] to be included in the aggregation.
    pub fn include_partial_signature(&mut self, partial_signature: PartialThresholdSignature) {
        self.state.partial_signatures.insert(&partial_signature.index, partial_signature.z);
    }

    /// Ensure that this signature aggregator is in a proper state to run the aggregation protocol.
    ///
    /// # Returns
    ///
    /// A Result whose Ok() value is a finalized aggregator, otherwise a
    /// `BTreeMap<u32, &'static str>` containing the participant indices of the misbehaving
    /// signers and a description of their misbehaviour.
    ///
    /// If the `BTreeMap` contains a key for `0`, this indicates that
    /// the aggregator did not have \(( t' \)) partial signers
    /// s.t. \(( t \le t' \le n \)).
    pub fn finalize(mut self) -> Result<SignatureAggregator<Finalized>, BTreeMap<u32, &'static str>> {
        let mut misbehaving_participants: BTreeMap<u32, &'static str> = BTreeMap::new();
        let remaining_signers = self.get_remaining_signers();

        // [DIFFERENT_TO_PAPER] We're reporting missing partial signatures which
        // could possibly be the fault of the aggregator, but here we explicitly
        // make it the aggregator's fault and problem.
        if ! remaining_signers.is_empty() {
            // We call the aggregator "participant 0" for the sake of error messages.
            misbehaving_participants.insert(0, "Missing remaining signer(s)");

            for signer in remaining_signers.iter() {
                misbehaving_participants.insert(signer.participant_index, "Missing partial signature");
            }
        }

        // Ensure that our new state is ordered and deduplicated.
        self.state.signers = self.get_signers().clone();

        for signer in self.state.signers.iter() {
            if self.state.public_keys.get(&signer.participant_index).is_none() {
                // XXX These should be Vec<&'static str> for full error reporting
                misbehaving_participants.insert(signer.participant_index, "Missing public key");
            }
        }

        if ! misbehaving_participants.is_empty() {
            return Err(misbehaving_participants);
        }

        let message_hash = compute_message_hash(&self.aggregator.context, &self.aggregator.message);

        Ok(SignatureAggregator { state: self.state, aggregator: Finalized { message_hash } })
    }
}

impl SignatureAggregator<Finalized> {
    /// Aggregate a set of previously-collected partial signatures.
    ///
    /// # Returns
    ///
    /// A Result whose Ok() value is a [`ThresholdSignature`], otherwise a
    /// `BTreeMap<u32, &'static str>` containing the participant indices of the misbehaving
    /// signers and a description of their misbehaviour.
    pub fn aggregate(&self) -> Result<ThresholdSignature, BTreeMap<u32, &'static str>> {
        let mut misbehaving_participants: BTreeMap<u32, &'static str> = BTreeMap::new();
        
        let (_, Rs) = compute_binding_factors_and_group_commitment(&self.aggregator.message_hash, &self.state.signers);
        let R: RistrettoPoint = Rs.values().sum();
        let c = compute_challenge(&self.aggregator.message_hash, &self.state.group_key, &R);
        let all_participant_indices: Vec<u32> = self.state.signers.iter().map(|x| x.participant_index).collect();
        let mut z = Scalar::zero();

        for signer in self.state.signers.iter() {
            // [DIFFERENT_TO_PAPER] We're not just pulling lambda out of our
            // ass, instead to get the correct algebraic properties to allow for
            // partial signature aggregation with t <= #participant <= n, we
            // have to do Langrangian polynomial interpolation.
            //
            // This unwrap() cannot fail, since the attempted division by zero in
            // the calculation of the Lagrange interpolation cannot happen,
            // because we use the typestate pattern,
            // i.e. SignatureAggregator<Initial>.finalize(), to ensure that
            // there are no duplicate signers, which is the only thing that
            // would cause a denominator of zero.
            let lambda = calculate_lagrange_coefficients(&signer.participant_index, &all_participant_indices).unwrap();

            // Similar to above, this unwrap() cannot fail, because
            // SignatureAggregator<Initial>.finalize() checks that we have
            // partial signature for every expected signer.
            let partial_sig = self.state.partial_signatures.get(&signer.participant_index).unwrap();

            // Again, this unwrap() cannot fail, because of the checks in finalize().
            let Y_i = self.state.public_keys.get(&signer.participant_index).unwrap();

            let check = &RISTRETTO_BASEPOINT_TABLE * partial_sig;

            // Again, this unwrap() cannot fail, because we check the
            // participant indexes against the expected ones in finalize().
            let R_i = Rs.get(&signer.participant_index).unwrap();

            if check == R_i + (Y_i * (c * lambda)) {
                z += partial_sig;
            } else {
                // XXX We don't really need the error string anymore, since there's only one failure mode.
                misbehaving_participants.insert(signer.participant_index, "Incorrect partial signature");
            }
        }

        match ! misbehaving_participants.is_empty() {
            true => Err(misbehaving_participants),
            false => Ok(ThresholdSignature {z, R}),
        }
    }
}

impl ThresholdSignature {
    /// Verify this [`ThresholdSignature`].
    ///
    /// # Returns
    ///
    /// A `Result` whose `Ok` value is an empty tuple if the threshold signature
    /// was successfully verified, otherwise a vector of the participant indices
    /// of any misbehaving participants.
    pub fn verify(&self, group_key: &GroupKey, message_hash: &[u8; 64]) -> Result<(), ()> {
        let c_prime = compute_challenge(&message_hash, &group_key, &self.R);
        let R_prime = RistrettoPoint::vartime_double_scalar_mul_basepoint(&c_prime, &-group_key.0, &self.z);

        match self.R.compress() == R_prime.compress() {
            true => Ok(()),
            false => Err(()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::keygen::Participant;
    use crate::keygen::{DistributedKeyGeneration, RoundOne};
    use crate::precomputation::{generate_commitment_share_lists, PublicCommitmentShareList};

    use curve25519_dalek::traits::Identity;

    use rand::rngs::OsRng;

    #[test]
    fn signing_and_verification_single_party() {
        let params = Parameters { n: 1, t: 1 };

        let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ");

        p1.proof_of_secret_key.as_ref().unwrap().verify(&p1.index, &p1.public_key().unwrap(), "Φ").unwrap();

        let mut participants: Vec<Participant> = vec![p1.clone()];
        let p1_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                 &p1_dh_sk,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut participants,
                                                                 "Φ").unwrap();
        let p1_my_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap().clone();
        let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).unwrap();
        let result = p1_state.finish();

        assert!(result.is_ok());

        let (group_key, p1_sk) = result.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("{:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_1_out_of_1() {
        let params = Parameters { n: 1, t: 1 };

        let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ");

        let mut participants: Vec<Participant> = vec![p1.clone()];
        let p1_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                 &p1_dh_sk,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut participants,
                                                                 "Φ").unwrap();
        let p1_my_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap().clone();
        let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish().unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_1_out_of_2() {
        let params = Parameters { n: 2, t: 1 };

        let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ");
        let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, "Φ");

        let mut participants: Vec<Participant> = vec!(p1.clone(), p2.clone());
        let p1_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                 &p1_dh_sk,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut participants,
                                                                 "Φ").unwrap();
        let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap();

        let p2_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                 &p2_dh_sk,
                                                                 &p2.index,
                                                                 &p2coeffs,
                                                                 &mut participants,
                                                                 "Φ").unwrap();
        let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

        let p1_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                               p2_their_encrypted_secret_shares[0].clone());
        let p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                               p2_their_encrypted_secret_shares[1].clone());

        let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish().unwrap();
        let (_, _p2_sk) = p2_state.finish().unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(p1_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_3_out_of_5() {
        let params = Parameters { n: 5, t: 3 };

        let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ");
        let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, "Φ");
        let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, "Φ");
        let (p4, p4coeffs, p4_dh_sk) = Participant::new_dealer(&params, 4, "Φ");
        let (p5, p5coeffs, p5_dh_sk) = Participant::new_dealer(&params, 5, "Φ");

        let mut participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone(), p5.clone());
        let p1_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                 &p1_dh_sk,
                                                                 &p1.index,
                                                                 &p1coeffs,
                                                                 &mut participants,
                                                                 "Φ").unwrap();
        let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap();

        let p2_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                 &p2_dh_sk,
                                                                 &p2.index,
                                                                 &p2coeffs,
                                                                 &mut participants,
                                                                 "Φ").unwrap();
        let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

        let  p3_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                  &p3_dh_sk,
                                                                  &p3.index,
                                                                  &p3coeffs,
                                                                  &mut participants,
                                                                  "Φ").unwrap();
        let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares().unwrap();

        let p4_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                 &p4_dh_sk,
                                                                 &p4.index,
                                                                 &p4coeffs,
                                                                 &mut participants,
                                                                 "Φ").unwrap();
        let p4_their_encrypted_secret_shares = p4_state.their_encrypted_secret_shares().unwrap();

        let p5_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                 &p5_dh_sk,
                                                                 &p5.index,
                                                                 &p5coeffs,
                                                                 &mut participants,
                                                                 "Φ").unwrap();
        let p5_their_encrypted_secret_shares = p5_state.their_encrypted_secret_shares().unwrap();

        let p1_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                       p2_their_encrypted_secret_shares[0].clone(),
                                       p3_their_encrypted_secret_shares[0].clone(),
                                       p4_their_encrypted_secret_shares[0].clone(),
                                       p5_their_encrypted_secret_shares[0].clone());

        let p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                       p2_their_encrypted_secret_shares[1].clone(),
                                       p3_their_encrypted_secret_shares[1].clone(),
                                       p4_their_encrypted_secret_shares[1].clone(),
                                       p5_their_encrypted_secret_shares[1].clone());

        let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[2].clone(),
                                       p2_their_encrypted_secret_shares[2].clone(),
                                       p3_their_encrypted_secret_shares[2].clone(),
                                       p4_their_encrypted_secret_shares[2].clone(),
                                       p5_their_encrypted_secret_shares[2].clone());

        let p4_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[3].clone(),
                                       p2_their_encrypted_secret_shares[3].clone(),
                                       p3_their_encrypted_secret_shares[3].clone(),
                                       p4_their_encrypted_secret_shares[3].clone(),
                                       p5_their_encrypted_secret_shares[3].clone());

        let p5_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[4].clone(),
                                       p2_their_encrypted_secret_shares[4].clone(),
                                       p3_their_encrypted_secret_shares[4].clone(),
                                       p4_their_encrypted_secret_shares[4].clone(),
                                       p5_their_encrypted_secret_shares[4].clone());

        let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).unwrap();
        let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares).unwrap();
        let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares).unwrap();
        let p4_state = p4_state.to_round_two(p4_my_encrypted_secret_shares).unwrap();
        let p5_state = p5_state.to_round_two(p5_my_encrypted_secret_shares).unwrap();

        let (group_key, p1_sk) = p1_state.finish().unwrap();
        let (_, _) = p2_state.finish().unwrap();
        let (_, p3_sk) = p3_state.finish().unwrap();
        let (_, p4_sk) = p4_state.finish().unwrap();
        let (_, _) = p5_state.finish().unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p3_public_comshares, mut p3_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
        let (p4_public_comshares, mut p4_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 4, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(3, p3_public_comshares.commitments[0], (&p3_sk).into());
        aggregator.include_signer(4, p4_public_comshares.commitments[0], (&p4_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();
        let p3_partial = p3_sk.sign(&message_hash, &group_key, &mut p3_secret_comshares, 0, signers).unwrap();
        let p4_partial = p4_sk.sign(&message_hash, &group_key, &mut p4_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p3_partial);
        aggregator.include_partial_signature(p4_partial);

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_2_out_of_3() {
        fn do_keygen() -> Result<(Parameters, SecretKey, SecretKey, SecretKey, GroupKey), ()> {
            let params = Parameters { n: 3, t: 2 };

            let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ");
            let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, "Φ");
            let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, "Φ");

            p2.proof_of_secret_key.as_ref().unwrap().verify(&p2.index, &p2.public_key().unwrap(), "Φ")?;
            p3.proof_of_secret_key.as_ref().unwrap().verify(&p3.index, &p3.public_key().unwrap(), "Φ")?;

            let mut participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                     &p1_dh_sk,
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut participants,
                                                                     "Φ").or(Err(()))?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let p2_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                     &p2_dh_sk,
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut participants,
                                                                     "Φ").or(Err(()))?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let  p3_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                      &p3_dh_sk,
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut participants,
                                                                      "Φ").or(Err(()))?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let p1_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                           p2_their_encrypted_secret_shares[0].clone(),
                                           p3_their_encrypted_secret_shares[0].clone());
            let p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                           p2_their_encrypted_secret_shares[1].clone(),
                                           p3_their_encrypted_secret_shares[1].clone());
            let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[2].clone(),
                                           p2_their_encrypted_secret_shares[2].clone(),
                                           p3_their_encrypted_secret_shares[2].clone());

            let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
            let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares).or(Err(()))?;
            let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

            let (p1_group_key, p1_secret_key) = p1_state.finish().or(Err(()))?;
            let (p2_group_key, p2_secret_key) = p2_state.finish().or(Err(()))?;
            let (p3_group_key, p3_secret_key) = p3_state.finish().or(Err(()))?;

            assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
            assert!(p2_group_key.0.compress() == p3_group_key.0.compress());

            Ok((params, p1_secret_key, p2_secret_key, p3_secret_key, p1_group_key))
        }
        let keygen_protocol = do_keygen();

        assert!(keygen_protocol.is_ok());

        let (params, p1_sk, p2_sk, _p3_sk, group_key) = keygen_protocol.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p2_public_comshares, mut p2_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);

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
    fn signing_and_verification_static_2_out_of_3() {
        fn do_keygen() -> Result<(Parameters, SecretKey, SecretKey, SecretKey, SecretKey, SecretKey, SecretKey, GroupKey), ()> {
            let params = Parameters { n: 3, t: 2 };

            let (dealer1, dealer1coeffs, dealer1_dh_sk) = Participant::new_dealer(&params, 1, "Φ");
            let (dealer2, dealer2coeffs, dealer2_dh_sk) = Participant::new_dealer(&params, 2, "Φ");
            let (dealer3, dealer3coeffs, dealer3_dh_sk) = Participant::new_dealer(&params, 3, "Φ");

            dealer1.proof_of_secret_key.as_ref().unwrap().verify(&dealer1.index, &dealer1.public_key().unwrap(), "Φ").or(Err(()))?;
            dealer2.proof_of_secret_key.as_ref().unwrap().verify(&dealer2.index, &dealer2.public_key().unwrap(), "Φ").or(Err(()))?;
            dealer3.proof_of_secret_key.as_ref().unwrap().verify(&dealer3.index, &dealer3.public_key().unwrap(), "Φ").or(Err(()))?;

            let mut dealers: Vec<Participant> = vec!(dealer1.clone(), dealer2.clone(), dealer3.clone());
            let dealer1_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                     &dealer1_dh_sk,
                                                                     &dealer1.index,
                                                                     &dealer1coeffs,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;
            let dealer1_their_encrypted_secret_shares = dealer1_state.their_encrypted_secret_shares()?;

            let dealer2_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                     &dealer2_dh_sk,
                                                                     &dealer2.index,
                                                                     &dealer2coeffs,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;
            let dealer2_their_encrypted_secret_shares = dealer2_state.their_encrypted_secret_shares()?;

            let dealer3_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                     &dealer3_dh_sk,
                                                                     &dealer3.index,
                                                                     &dealer3coeffs,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;
            let dealer3_their_encrypted_secret_shares = dealer3_state.their_encrypted_secret_shares()?;

            let dealer1_my_encrypted_secret_shares = vec!(dealer1_their_encrypted_secret_shares[0].clone(),
                                                          dealer2_their_encrypted_secret_shares[0].clone(),
                                                          dealer3_their_encrypted_secret_shares[0].clone());
            let dealer2_my_encrypted_secret_shares = vec!(dealer1_their_encrypted_secret_shares[1].clone(),
                                                          dealer2_their_encrypted_secret_shares[1].clone(),
                                                          dealer3_their_encrypted_secret_shares[1].clone());
            let dealer3_my_encrypted_secret_shares = vec!(dealer1_their_encrypted_secret_shares[2].clone(),
                                                          dealer2_their_encrypted_secret_shares[2].clone(),
                                                          dealer3_their_encrypted_secret_shares[2].clone());

            let dealer1_state = dealer1_state.to_round_two(dealer1_my_encrypted_secret_shares).or(Err(()))?;
            let dealer2_state = dealer2_state.to_round_two(dealer2_my_encrypted_secret_shares).or(Err(()))?;
            let dealer3_state = dealer3_state.to_round_two(dealer3_my_encrypted_secret_shares).or(Err(()))?;

            let (dealer1_group_key, dealer1_secret_key) = dealer1_state.finish().or(Err(()))?;
            let (dealer2_group_key, dealer2_secret_key) = dealer2_state.finish().or(Err(()))?;
            let (dealer3_group_key, dealer3_secret_key) = dealer3_state.finish().or(Err(()))?;

            assert!(dealer1_group_key.0.compress() == dealer2_group_key.0.compress());
            assert!(dealer2_group_key.0.compress() == dealer3_group_key.0.compress());

            let (signer1, signer1_dh_sk) = Participant::new_signer(&params, 1, "Φ");
            let (signer2, signer2_dh_sk) = Participant::new_signer(&params, 2, "Φ");
            let (signer3, signer3_dh_sk) = Participant::new_signer(&params, 3, "Φ");

            let mut signers: Vec<Participant> = vec!(signer1.clone(), signer2.clone(), signer3.clone());

            let (dealer1_for_signers, dealer1_encrypted_shares_for_signers) =
                Participant::reshare(&params, dealer1_secret_key.clone(), &mut signers, "Φ").map_err(|_| ())?;
            let (dealer2_for_signers, dealer2_encrypted_shares_for_signers) =
                Participant::reshare(&params, dealer2_secret_key.clone(), &mut signers, "Φ").map_err(|_| ())?;
            let (dealer3_for_signers, dealer3_encrypted_shares_for_signers) =
                Participant::reshare(&params, dealer3_secret_key.clone(), &mut signers, "Φ").map_err(|_| ())?;

            let mut dealers: Vec<Participant> = vec!(dealer1_for_signers, dealer2_for_signers, dealer3_for_signers);
            let signer1_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &signer1_dh_sk,
                                                                     &signer1.index,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;

            let signer2_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &signer2_dh_sk,
                                                                     &signer2.index,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;

            let signer3_state = DistributedKeyGeneration::<RoundOne>::new(&params,
                                                                     &signer3_dh_sk,
                                                                     &signer3.index,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;

            let signer1_my_encrypted_secret_shares = vec!(dealer1_encrypted_shares_for_signers[0].clone(),
                                                          dealer2_encrypted_shares_for_signers[0].clone(),
                                                          dealer3_encrypted_shares_for_signers[0].clone());
            let signer2_my_encrypted_secret_shares = vec!(dealer1_encrypted_shares_for_signers[1].clone(),
                                                          dealer2_encrypted_shares_for_signers[1].clone(),
                                                          dealer3_encrypted_shares_for_signers[1].clone());
            let signer3_my_encrypted_secret_shares = vec!(dealer1_encrypted_shares_for_signers[2].clone(),
                                                          dealer2_encrypted_shares_for_signers[2].clone(),
                                                          dealer3_encrypted_shares_for_signers[2].clone());

            let signer1_state = signer1_state.to_round_two(signer1_my_encrypted_secret_shares).or(Err(()))?;
            let signer2_state = signer2_state.to_round_two(signer2_my_encrypted_secret_shares).or(Err(()))?;
            let signer3_state = signer3_state.to_round_two(signer3_my_encrypted_secret_shares).or(Err(()))?;

            let (signer1_group_key, signer1_secret_key) = signer1_state.finish().or(Err(()))?;
            let (signer2_group_key, signer2_secret_key) = signer2_state.finish().or(Err(()))?;
            let (signer3_group_key, signer3_secret_key) = signer3_state.finish().or(Err(()))?;

            assert!(signer1_group_key.0.compress() == signer2_group_key.0.compress());
            assert!(signer2_group_key.0.compress() == signer3_group_key.0.compress());

            assert!(signer1_group_key.0.compress() == dealer1_group_key.0.compress());

            Ok(
                (
                    params,
                    dealer1_secret_key,
                    dealer2_secret_key,
                    dealer3_secret_key,
                    signer1_secret_key,
                    signer2_secret_key,
                    signer3_secret_key,
                    dealer1_group_key
                )
            )
        }
        let keygen_protocol = do_keygen();

        assert!(keygen_protocol.is_ok());

        let (params, d1_sk, d2_sk, _d3_sk, s1_sk, s2_sk, _s3_sk, group_key) = keygen_protocol.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (d1_public_comshares, mut d1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (d2_public_comshares, mut d2_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, d1_public_comshares.commitments[0], (&d1_sk).into());
        aggregator.include_signer(2, d2_public_comshares.commitments[0], (&d2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let d1_partial = d1_sk.sign(&message_hash, &group_key, &mut d1_secret_comshares, 0, signers).unwrap();
        let d2_partial = d2_sk.sign(&message_hash, &group_key, &mut d2_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(d1_partial);
        aggregator.include_partial_signature(d2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("Dealer's signing session: {:?}", verification_result);

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (s1_public_comshares, mut s1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (s2_public_comshares, mut s2_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, s1_public_comshares.commitments[0], (&s1_sk).into());
        aggregator.include_signer(2, s2_public_comshares.commitments[0], (&s2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let s1_partial = s1_sk.sign(&message_hash, &group_key, &mut s1_secret_comshares, 0, signers).unwrap();
        let s2_partial = s2_sk.sign(&message_hash, &group_key, &mut s2_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(s1_partial);
        aggregator.include_partial_signature(s2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("Signers's signing session: {:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn signing_and_verification_static_2_out_of_3_into_3_out_of_5() {
        fn do_keygen() -> 
            Result<
                (
                    Parameters,
                    Parameters,
                    SecretKey,
                    SecretKey,
                    SecretKey,
                    SecretKey,
                    SecretKey,
                    SecretKey,
                    SecretKey,
                    SecretKey,
                    GroupKey
                ),
                ()>
        {
            let params_dealers = Parameters { n: 3, t: 2 };

            let (dealer1, dealer1coeffs, dealer1_dh_sk) = Participant::new_dealer(&params_dealers, 1, "Φ");
            let (dealer2, dealer2coeffs, dealer2_dh_sk) = Participant::new_dealer(&params_dealers, 2, "Φ");
            let (dealer3, dealer3coeffs, dealer3_dh_sk) = Participant::new_dealer(&params_dealers, 3, "Φ");

            dealer1.proof_of_secret_key.as_ref().unwrap().verify(&dealer1.index, &dealer1.public_key().unwrap(), "Φ").or(Err(()))?;
            dealer2.proof_of_secret_key.as_ref().unwrap().verify(&dealer2.index, &dealer2.public_key().unwrap(), "Φ").or(Err(()))?;
            dealer3.proof_of_secret_key.as_ref().unwrap().verify(&dealer3.index, &dealer3.public_key().unwrap(), "Φ").or(Err(()))?;

            let mut dealers: Vec<Participant> = vec!(dealer1.clone(), dealer2.clone(), dealer3.clone());
            let dealer1_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params_dealers,
                                                                     &dealer1_dh_sk,
                                                                     &dealer1.index,
                                                                     &dealer1coeffs,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;
            let dealer1_their_encrypted_secret_shares = dealer1_state.their_encrypted_secret_shares()?;

            let dealer2_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params_dealers,
                                                                     &dealer2_dh_sk,
                                                                     &dealer2.index,
                                                                     &dealer2coeffs,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;
            let dealer2_their_encrypted_secret_shares = dealer2_state.their_encrypted_secret_shares()?;

            let dealer3_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params_dealers,
                                                                     &dealer3_dh_sk,
                                                                     &dealer3.index,
                                                                     &dealer3coeffs,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;
            let dealer3_their_encrypted_secret_shares = dealer3_state.their_encrypted_secret_shares()?;

            let dealer1_my_encrypted_secret_shares = vec!(dealer1_their_encrypted_secret_shares[0].clone(),
                                                          dealer2_their_encrypted_secret_shares[0].clone(),
                                                          dealer3_their_encrypted_secret_shares[0].clone());
            let dealer2_my_encrypted_secret_shares = vec!(dealer1_their_encrypted_secret_shares[1].clone(),
                                                          dealer2_their_encrypted_secret_shares[1].clone(),
                                                          dealer3_their_encrypted_secret_shares[1].clone());
            let dealer3_my_encrypted_secret_shares = vec!(dealer1_their_encrypted_secret_shares[2].clone(),
                                                          dealer2_their_encrypted_secret_shares[2].clone(),
                                                          dealer3_their_encrypted_secret_shares[2].clone());

            let dealer1_state = dealer1_state.to_round_two(dealer1_my_encrypted_secret_shares).or(Err(()))?;
            let dealer2_state = dealer2_state.to_round_two(dealer2_my_encrypted_secret_shares).or(Err(()))?;
            let dealer3_state = dealer3_state.to_round_two(dealer3_my_encrypted_secret_shares).or(Err(()))?;

            let (dealer1_group_key, dealer1_secret_key) = dealer1_state.finish().or(Err(()))?;
            let (dealer2_group_key, dealer2_secret_key) = dealer2_state.finish().or(Err(()))?;
            let (dealer3_group_key, dealer3_secret_key) = dealer3_state.finish().or(Err(()))?;

            assert!(dealer1_group_key.0.compress() == dealer2_group_key.0.compress());
            assert!(dealer2_group_key.0.compress() == dealer3_group_key.0.compress());

            let params_signers = Parameters { n: 5, t: 3 };
            let (signer1, signer1_dh_sk) = Participant::new_signer(&params_signers, 1, "Φ");
            let (signer2, signer2_dh_sk) = Participant::new_signer(&params_signers, 2, "Φ");
            let (signer3, signer3_dh_sk) = Participant::new_signer(&params_signers, 3, "Φ");
            let (signer4, signer4_dh_sk) = Participant::new_signer(&params_signers, 4, "Φ");
            let (signer5, signer5_dh_sk) = Participant::new_signer(&params_signers, 5, "Φ");

            let mut signers: Vec<Participant> = vec!(signer1.clone(), signer2.clone(), signer3.clone(), signer4.clone(), signer5.clone());

            let (dealer1_for_signers, dealer1_encrypted_shares_for_signers) =
                Participant::reshare(&params_signers, dealer1_secret_key.clone(), &mut signers, "Φ").map_err(|_| ())?;
            let (dealer2_for_signers, dealer2_encrypted_shares_for_signers) =
                Participant::reshare(&params_signers, dealer2_secret_key.clone(), &mut signers, "Φ").map_err(|_| ())?;
            let (dealer3_for_signers, dealer3_encrypted_shares_for_signers) =
                Participant::reshare(&params_signers, dealer3_secret_key.clone(), &mut signers, "Φ").map_err(|_| ())?;

            let mut dealers: Vec<Participant> = vec!(dealer1_for_signers, dealer2_for_signers, dealer3_for_signers);
            let signer1_state = DistributedKeyGeneration::<RoundOne>::new(&params_dealers,
                                                                     &signer1_dh_sk,
                                                                     &signer1.index,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;

            let signer2_state = DistributedKeyGeneration::<RoundOne>::new(&params_dealers,
                                                                     &signer2_dh_sk,
                                                                     &signer2.index,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;

            let signer3_state = DistributedKeyGeneration::<RoundOne>::new(&params_dealers,
                                                                     &signer3_dh_sk,
                                                                     &signer3.index,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;

            let signer4_state = DistributedKeyGeneration::<RoundOne>::new(&params_dealers,
                                                                     &signer4_dh_sk,
                                                                     &signer4.index,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;

            let signer5_state = DistributedKeyGeneration::<RoundOne>::new(&params_dealers,
                                                                     &signer5_dh_sk,
                                                                     &signer5.index,
                                                                     &mut dealers,
                                                                     "Φ").or(Err(()))?;

            let signer1_my_encrypted_secret_shares = vec!(dealer1_encrypted_shares_for_signers[0].clone(),
                                                          dealer2_encrypted_shares_for_signers[0].clone(),
                                                          dealer3_encrypted_shares_for_signers[0].clone());
            let signer2_my_encrypted_secret_shares = vec!(dealer1_encrypted_shares_for_signers[1].clone(),
                                                          dealer2_encrypted_shares_for_signers[1].clone(),
                                                          dealer3_encrypted_shares_for_signers[1].clone());
            let signer3_my_encrypted_secret_shares = vec!(dealer1_encrypted_shares_for_signers[2].clone(),
                                                          dealer2_encrypted_shares_for_signers[2].clone(),
                                                          dealer3_encrypted_shares_for_signers[2].clone());
            let signer4_my_encrypted_secret_shares = vec!(dealer1_encrypted_shares_for_signers[3].clone(),
                                                          dealer2_encrypted_shares_for_signers[3].clone(),
                                                          dealer3_encrypted_shares_for_signers[3].clone());
            let signer5_my_encrypted_secret_shares = vec!(dealer1_encrypted_shares_for_signers[4].clone(),
                                                          dealer2_encrypted_shares_for_signers[4].clone(),
                                                          dealer3_encrypted_shares_for_signers[4].clone());

            let signer1_state = signer1_state.to_round_two(signer1_my_encrypted_secret_shares).or(Err(()))?;
            let signer2_state = signer2_state.to_round_two(signer2_my_encrypted_secret_shares).or(Err(()))?;
            let signer3_state = signer3_state.to_round_two(signer3_my_encrypted_secret_shares).or(Err(()))?;
            let signer4_state = signer4_state.to_round_two(signer4_my_encrypted_secret_shares).or(Err(()))?;
            let signer5_state = signer5_state.to_round_two(signer5_my_encrypted_secret_shares).or(Err(()))?;

            let (signer1_group_key, signer1_secret_key) = signer1_state.finish().or(Err(()))?;
            let (signer2_group_key, signer2_secret_key) = signer2_state.finish().or(Err(()))?;
            let (signer3_group_key, signer3_secret_key) = signer3_state.finish().or(Err(()))?;
            let (signer4_group_key, signer4_secret_key) = signer4_state.finish().or(Err(()))?;
            let (signer5_group_key, signer5_secret_key) = signer5_state.finish().or(Err(()))?;

            assert!(signer1_group_key.0.compress() == signer2_group_key.0.compress());
            assert!(signer2_group_key.0.compress() == signer3_group_key.0.compress());
            assert!(signer3_group_key.0.compress() == signer4_group_key.0.compress());
            assert!(signer4_group_key.0.compress() == signer5_group_key.0.compress());

            assert!(signer1_group_key.0.compress() == dealer1_group_key.0.compress());

            Ok((params_dealers, params_signers, dealer1_secret_key, dealer2_secret_key, dealer3_secret_key, signer1_secret_key, signer2_secret_key, signer3_secret_key, signer4_secret_key, signer5_secret_key, dealer1_group_key))
        }
        let keygen_protocol = do_keygen();

        assert!(keygen_protocol.is_ok());

        let (d_params, s_params, d1_sk, d2_sk, _d3_sk, s1_sk, s2_sk, s3_sk, _s4_sk, _s5_sk, group_key) = keygen_protocol.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (d1_public_comshares, mut d1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (d2_public_comshares, mut d2_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator = SignatureAggregator::new(d_params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, d1_public_comshares.commitments[0], (&d1_sk).into());
        aggregator.include_signer(2, d2_public_comshares.commitments[0], (&d2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let d1_partial = d1_sk.sign(&message_hash, &group_key, &mut d1_secret_comshares, 0, signers).unwrap();
        let d2_partial = d2_sk.sign(&message_hash, &group_key, &mut d2_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(d1_partial);
        aggregator.include_partial_signature(d2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("Dealer's signing session: {:?}", verification_result);

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (s1_public_comshares, mut s1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (s2_public_comshares, mut s2_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
        let (s3_public_comshares, mut s3_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);

        let mut aggregator = SignatureAggregator::new(s_params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, s1_public_comshares.commitments[0], (&s1_sk).into());
        aggregator.include_signer(2, s2_public_comshares.commitments[0], (&s2_sk).into());
        aggregator.include_signer(3, s3_public_comshares.commitments[0], (&s3_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let s1_partial = s1_sk.sign(&message_hash, &group_key, &mut s1_secret_comshares, 0, signers).unwrap();
        let s2_partial = s2_sk.sign(&message_hash, &group_key, &mut s2_secret_comshares, 0, signers).unwrap();
        let s3_partial = s3_sk.sign(&message_hash, &group_key, &mut s3_secret_comshares, 0, signers).unwrap();

        aggregator.include_partial_signature(s1_partial);
        aggregator.include_partial_signature(s2_partial);
        aggregator.include_partial_signature(s3_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("Signers's signing session: {:?}", verification_result);

        assert!(verification_result.is_ok());
    }

    #[test]
    fn aggregator_get_signers() {
        let params = Parameters { n: 3, t: 2 };
        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let (p1_public_comshares, _) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p2_public_comshares, _) = generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator = SignatureAggregator::new(params, GroupKey(RistrettoPoint::identity()), &context[..], &message[..]);

        let p1_sk = SecretKey{ index: 1, key: Scalar::random(&mut OsRng) };
        let p2_sk = SecretKey{ index: 2, key: Scalar::random(&mut OsRng) };

        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());
        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());

        let signers = aggregator.get_signers();

        // The signers should be deduplicated.
        assert!(signers.len() == 2);

        // The indices should match and be in sorted order.
        assert!(signers[0].participant_index == 1);
        assert!(signers[1].participant_index == 2);

        // Participant 1 should have the correct precomputed shares.
        assert!(signers[0].published_commitment_share.0 == p1_public_comshares.commitments[0].0);
        assert!(signers[0].published_commitment_share.1 == p1_public_comshares.commitments[0].1);

        // Same for participant 2.
        assert!(signers[1].published_commitment_share.0 == p2_public_comshares.commitments[0].0);
        assert!(signers[1].published_commitment_share.1 == p2_public_comshares.commitments[0].1);
    }

    #[test]
    fn serialisation() {
        fn do_keygen() -> Result<(Parameters, SecretKey, SecretKey, SecretKey, GroupKey), ()> {
            let params = Parameters { n: 3, t: 2 };

            let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ");
            let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, "Φ");
            let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, "Φ");

            p2.proof_of_secret_key.as_ref().unwrap().verify(&p2.index, &p2.public_key().unwrap(), "Φ")?;
            p3.proof_of_secret_key.as_ref().unwrap().verify(&p3.index, &p3.public_key().unwrap(), "Φ")?;

            let mut participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone());
            let p1_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                     &p1_dh_sk,
                                                                     &p1.index,
                                                                     &p1coeffs,
                                                                     &mut participants,
                                                                     "Φ").or(Err(()))?;
            let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares()?;

            let p2_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                     &p2_dh_sk,
                                                                     &p2.index,
                                                                     &p2coeffs,
                                                                     &mut participants,
                                                                     "Φ").or(Err(()))?;
            let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares()?;

            let  p3_state = DistributedKeyGeneration::<RoundOne>::new_initial(&params,
                                                                      &p3_dh_sk,
                                                                      &p3.index,
                                                                      &p3coeffs,
                                                                      &mut participants,
                                                                      "Φ").or(Err(()))?;
            let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares()?;

            let p1_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                           p2_their_encrypted_secret_shares[0].clone(),
                                           p3_their_encrypted_secret_shares[0].clone());
            let p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                           p2_their_encrypted_secret_shares[1].clone(),
                                           p3_their_encrypted_secret_shares[1].clone());
            let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[2].clone(),
                                           p2_their_encrypted_secret_shares[2].clone(),
                                           p3_their_encrypted_secret_shares[2].clone());

            let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).or(Err(()))?;
            let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares).or(Err(()))?;
            let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares).or(Err(()))?;

            let (p1_group_key, p1_secret_key) = p1_state.finish().or(Err(()))?;
            let (p2_group_key, p2_secret_key) = p2_state.finish().or(Err(()))?;
            let (p3_group_key, p3_secret_key) = p3_state.finish().or(Err(()))?;

            assert!(p1_group_key.0.compress() == p2_group_key.0.compress());
            assert!(p2_group_key.0.compress() == p3_group_key.0.compress());

            Ok((params, p1_secret_key, p2_secret_key, p3_secret_key, p1_group_key))
        }
        let keygen_protocol = do_keygen();

        assert!(keygen_protocol.is_ok());

        let (params, p1_sk, p2_sk, _p3_sk, group_key) = keygen_protocol.unwrap();

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        let (p2_public_comshares, mut p2_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
        aggregator.include_signer(2, p2_public_comshares.commitments[0], (&p2_sk).into());

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();
        let p2_partial = p2_sk.sign(&message_hash, &group_key, &mut p2_secret_comshares, 0, signers).unwrap();

        // Check serialisation

        let bytes = p1_secret_comshares.to_bytes();
        assert_eq!(p1_secret_comshares, SecretCommitmentShareList::from_bytes(&bytes).unwrap());

        let bytes = p1_public_comshares.to_bytes();
        assert_eq!(p1_public_comshares, PublicCommitmentShareList::from_bytes(&bytes).unwrap());

        let bytes = p1_partial.to_bytes();
        assert_eq!(p1_partial, PartialThresholdSignature::from_bytes(bytes).unwrap());

        // Continue signature

        aggregator.include_partial_signature(p1_partial);
        aggregator.include_partial_signature(p2_partial);

        let aggregator = aggregator.finalize().unwrap();
        let signing_result = aggregator.aggregate();

        assert!(signing_result.is_ok());

        let threshold_signature = signing_result.unwrap();
        let verification_result = threshold_signature.verify(&group_key, &message_hash);

        println!("{:?}", verification_result);

        assert!(verification_result.is_ok());

        // Check serialisation

        let bytes = threshold_signature.to_bytes();
        assert_eq!(threshold_signature, ThresholdSignature::from_bytes(bytes).unwrap());

    }
}
