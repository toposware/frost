// -*- mode: rust; -*-
//
// This file is part of ice-frost.
// Copyright (c) 2017-2019 isis lovecruft
// Copyright (c) 2021-2023 Toposware Inc.
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Toposware developers <dev@toposware.com>

//! A Rust implementation of Static **[ICE-FROST]**: **I**dentifiable **C**heating **E**ntity **F**lexible **R**ound-**O**ptimised **S**chnorr **T**hreshold signatures.
//!
//! Threshold signatures are a cryptographic construction wherein a subset, \\( t \\),
//! of a group of \\( n \\) signers can produce a valid signature.  For example, if
//! Alice, Bob, and Carol set up key materials for a 2-out-of-3 threshold signature
//! scheme, then the same public group key can be used to verify a message signed
//! by Alice and Carol as a different message signed by Bob and Carol.
//!
//! FROST signatures are unique in that they manage to optimise threshold signing into
//! a single round, while still safeguarding against [various] [cryptographic] [attacks]
//! that effect other threshold signing schemes, by utilising [commitments] to
//! pre-computed secret shares.
//!
//! For a more in-depth explanation of the mathematics involved, please see
//! [the keygen module](keygen/index.html), [the precomputation module](precomputation/index.html),
//! and [the signature module](signature/index.html).
//!
//! [FROST]: https://eprint.iacr.org/2020/852
//! [ICE-FROST]: https://eprint.iacr.org/2021/1658
//! [various]: https://eprint.iacr.org/2018/417
//! [cryptographic]: https://eprint.iacr.org/2020/945
//! [attacks]: https://www.researchgate.net/profile/Claus_Schnorr/publication/2900710_Security_of_Blind_Discrete_Log_Signatures_against_Interactive_Attacks/links/54231e540cf26120b7a6bb47.pdf
//! [commitments]: https://en.wikipedia.org/wiki/Commitment_scheme
//!
//! # Usage
//!
//! Alice, Bob, and Carol would like to set up a threshold signing scheme where
//! at least two of them need to sign on a given message to produce a valid
//! signature.
//!
//! ```rust
//! use ice_frost::Parameters;
//!
//! let params = Parameters { t: 2, n: 3 };
//! ```
//!
//! ## Distributed Key Generation
//!
//! Alice, Bob, and Carol each generate their secret polynomial coefficients
//! (which make up each individual's personal secret key) and commitments to
//! them, as well as a zero-knowledge proof of their personal secret key.  Out
//! of scope, they each need to agree upon their *participant index* which is
//! some non-zero integer unique to each of them (these are the `1`, `2`, and
//! `3` in the following examples).
//!
//! ```rust
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use rand::rngs::OsRng;
//! #
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//!
//! // Each application developer should choose a context string as unique to their usage
//! // as possible (instead of the below "Φ"), in order to prevent replay attacks, as well as
//! // a good cryptographic source of randomness.
//! let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! ```
//!
//! They send these values to each of the other participants (also out of scope
//! for this library), or otherwise publish them publicly somewhere.
//!
//! Note that they should only send the `alice`, `bob`, and `carol` structs, *not*
//! the `alice_coefficients`, etc., as the latter are their personal secret keys.
//!
//! Bob and Carol verify Alice's zero-knowledge proof by doing:
//!
//! ```rust
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! alice.proof_of_secret_key.as_ref().unwrap()
//!     .verify(&alice.index, &alice.public_key().unwrap(), "Φ").or(Err(()))?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Similarly, Alice and Carol verify Bob's proof:
//!
//! ```rust
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! bob.proof_of_secret_key.as_ref().unwrap()
//!     .verify(&bob.index, &bob.public_key().unwrap(), "Φ").or(Err(()))?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! And, again, Alice and Bob verify Carol's proof:
//!
//! ```rust
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! carol.proof_of_secret_key.as_ref().unwrap()
//!     .verify(&carol.index, &carol.public_key().unwrap(), "Φ").or(Err(()))?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alice enters round one of the distributed key generation protocol:
//!
//! ```rust
//! use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Error;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), Error> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//!
//! let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! let (alice_state, participant_lists) =
//!     DistributedKeyGeneration::<_>::new_initial(
//!         &params,
//!         &alice_dh_sk,
//!         &alice.index,
//!         &alice_coefficients,
//!         &participants,
//!         "Φ",
//!         &mut rng,
//!     )?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alice then collects the secret shares which they send to the other participants:
//!
//! ```rust
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Bob and Carol each do the same:
//!
//! ```rust
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Error;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), Error> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! let (bob_state, participant_lists) =
//!     DistributedKeyGeneration::<_>::new_initial(
//!         &params,
//!         &bob_dh_sk,
//!         &bob.index,
//!         &bob_coefficients,
//!         &participants,
//!         "Φ",
//!         &mut rng,
//!     )?;
//! # Ok(()) }
//! # fn do_test2() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//!
//! let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//!
//! // send_to_alice(bob_their_encrypted_secret_shares[0]);
//! // send_to_carol(bob_their_encrypted_secret_shares[1]);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); assert!(do_test2().is_ok()); }
//! ```
//!
//! and
//!
//! ```rust
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Error;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), Error> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! let (carol_state, participant_lists) =
//!     DistributedKeyGeneration::<_>::new_initial(
//!         &params,
//!         &carol_dh_sk,
//!         &carol.index,
//!         &carol_coefficients,
//!         &participants,
//!         "Φ",
//!         &mut rng,
//!     )?;
//! # Ok(()) }
//! # fn do_test2() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//!
//! let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//!
//! // send_to_alice(carol_their_encrypted_secret_shares[0]);
//! // send_to_bob(carol_their_encrypted_secret_shares[1]);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); assert!(do_test2().is_ok()); }
//! ```
//!
//! Each participant now has a vector of secret shares given to them by the other participants:
//!
//! ```rust
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//! let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//!                                   bob_their_encrypted_secret_shares[0].clone(),
//!                                   carol_their_encrypted_secret_shares[0].clone());
//! let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//!                                 bob_their_encrypted_secret_shares[1].clone(),
//!                                 carol_their_encrypted_secret_shares[1].clone());
//! let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//!                                   bob_their_encrypted_secret_shares[2].clone(),
//!                                   carol_their_encrypted_secret_shares[2].clone());
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! The participants then use these secret shares from the other participants to advance to
//! round two of the distributed key generation protocol.
//!
//! ```rust
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Each participant can now derive their long-lived, personal secret keys and the group's
//! public key.  They should all derive the same group public key.  They
//! also derive their [`IndividualPublicKey`]s from their [`IndividualSecretKey`]s.
//!
//! ```rust
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! #
//! let (alice_group_key, alice_secret_key) = alice_state.finish().or(Err(()))?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish().or(Err(()))?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish().or(Err(()))?;
//!
//! assert!(alice_group_key == bob_group_key);
//! assert!(carol_group_key == bob_group_key);
//!
//! let alice_public_key = alice_secret_key.to_public();
//! let bob_public_key = bob_secret_key.to_public();
//! let carol_public_key = carol_secret_key.to_public();
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! ## Distributed Key Resharing
//!
//! Alice, Bob, and Carol perform between them their distributed key generation
//! and end up with their long-lived, personal secret keys and the group's public
//! key. They now want to allow a different set of people, namely Alexis, Barbara,
//! Claire and David, to sign with respect to the same group's public key.
//!
//! ```rust
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//!
//! // Perform regular 2-out-of-3 DKG...
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//!
//! let (alice_group_key, alice_secret_key) = alice_state.finish().or(Err(()))?;
//! let (bob_group_key, bob_secret_key) = bob_state.finish().or(Err(()))?;
//! let (carol_group_key, carol_secret_key) = carol_state.finish().or(Err(()))?;
//!
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! // Instantiate new configuration parameters and create a new set of signers
//! let new_params = Parameters { t: 3, n: 4 };
//!
//! let (alexis, alexis_dh_sk) = Participant::new_signer(&new_params, 1, "Φ", &mut rng);
//! let (barbara, barbara_dh_sk) = Participant::new_signer(&new_params, 2, "Φ", &mut rng);
//! let (claire, claire_dh_sk) = Participant::new_signer(&new_params, 3, "Φ", &mut rng);
//! let (david, david_dh_sk) = Participant::new_signer(&new_params, 4, "Φ", &mut rng);
//!
//! let signers: Vec<Participant> =
//!     vec!(alexis.clone(), barbara.clone(), claire.clone(), david.clone());
//!
//! let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//!     Participant::reshare(&new_params, alice_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//!
//! let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//!     Participant::reshare(&new_params, bob_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//!
//! let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//!     Participant::reshare(&new_params, carol_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alexis, Barbara, Claire and David, can now instantiate their distributed key
//! generation protocol with respect to the previous set of dealers.
//!
//! ```rust
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish().or(Err(()))?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish().or(Err(()))?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish().or(Err(()))?;
//! #
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! # // Instantiate new configuration parameters and create a set of signers
//! # let new_params = Parameters { t: 3, n: 4 };
//! #
//! # let (alexis, alexis_dh_sk) = Participant::new_signer(&new_params, 1, "Φ", &mut rng);
//! # let (barbara, barbara_dh_sk) = Participant::new_signer(&new_params, 2, "Φ", &mut rng);
//! # let (claire, claire_dh_sk) = Participant::new_signer(&new_params, 3, "Φ", &mut rng);
//! # let (david, david_dh_sk) = Participant::new_signer(&new_params, 4, "Φ", &mut rng);
//! #
//! # let signers: Vec<Participant> = vec!(alexis.clone(), barbara.clone(), claire.clone(), david.clone());
//! # let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, alice_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//! # let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, bob_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//! # let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, carol_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//! #
//! let dealers: Vec<Participant> =
//!     vec!(alice_as_dealer.clone(), bob_as_dealer.clone(), carol_as_dealer.clone());
//!
//! let (alexis_state, participant_lists) =
//!     DistributedKeyGeneration::<_>::new(
//!         &params,
//!         &alexis_dh_sk,
//!         &alexis.index,
//!         &dealers,
//!         "Φ",
//!         &mut rng,
//!     )
//!     .or(Err(()))?;
//!
//! let (barbara_state, participant_lists) =
//!     DistributedKeyGeneration::<_>::new(
//!         &params,
//!         &barbara_dh_sk,
//!         &barbara.index,
//!         &dealers,
//!         "Φ",
//!         &mut rng,
//!     )
//!     .or(Err(()))?;
//!
//! let (claire_state, participant_lists) =
//!     DistributedKeyGeneration::<_>::new(
//!         &params,
//!         &claire_dh_sk,
//!         &claire.index,
//!         &dealers,
//!         "Φ",
//!         &mut rng,
//!     )
//!     .or(Err(()))?;
//!
//! let (david_state, participant_lists) =
//!     DistributedKeyGeneration::<_>::new(
//!         &params,
//!         &david_dh_sk,
//!         &david.index,
//!         &dealers,
//!         "Φ",
//!         &mut rng,
//!     )
//!     .or(Err(()))?;
//! #
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alexis, Barbara, Claire and David, can then use the encrypted secret
//! shares of the previous dealers to proceed to the Round 2 of the
//! distributed key resharing protocol.
//!
//! ```rust
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish().or(Err(()))?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish().or(Err(()))?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish().or(Err(()))?;
//! #
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! # // Instantiate new configuration parameters and create a set of signers
//! # let new_params = Parameters { t: 3, n: 4 };
//! #
//! # let (alexis, alexis_dh_sk) = Participant::new_signer(&new_params, 1, "Φ", &mut rng);
//! # let (barbara, barbara_dh_sk) = Participant::new_signer(&new_params, 2, "Φ", &mut rng);
//! # let (claire, claire_dh_sk) = Participant::new_signer(&new_params, 3, "Φ", &mut rng);
//! # let (david, david_dh_sk) = Participant::new_signer(&new_params, 4, "Φ", &mut rng);
//! #
//! # let signers: Vec<Participant> = vec!(alexis.clone(), barbara.clone(), claire.clone(), david.clone());
//! # let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, alice_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//! # let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, bob_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//! # let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, carol_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//! #
//! # let dealers: Vec<Participant> =
//! #     vec!(alice_as_dealer.clone(), bob_as_dealer.clone(), carol_as_dealer.clone());
//! # let (alexis_state, participant_lists) = DistributedKeyGeneration::<_>::new(&params, &alexis_dh_sk, &alexis.index,
//! #                                                    &dealers, "Φ", &mut rng).or(Err(()))?;
//! #
//! # let (barbara_state, participant_lists) = DistributedKeyGeneration::<_>::new(&params, &barbara_dh_sk, &barbara.index,
//! #                                                    &dealers, "Φ", &mut rng).or(Err(()))?;
//! #
//! # let (claire_state, participant_lists) = DistributedKeyGeneration::<_>::new(&params, &claire_dh_sk, &claire.index,
//! #                                                      &dealers, "Φ", &mut rng).or(Err(()))?;
//! #
//! # let (david_state, participant_lists) = DistributedKeyGeneration::<_>::new(&params, &david_dh_sk, &david.index,
//! #                                                      &dealers, "Φ", &mut rng).or(Err(()))?;
//! #
//! # let alexis_my_encrypted_secret_shares = vec!(alice_encrypted_shares[0].clone(),
//! #                                   bob_encrypted_shares[0].clone(),
//! #                                   carol_encrypted_shares[0].clone());
//! # let barbara_my_encrypted_secret_shares = vec!(alice_encrypted_shares[1].clone(),
//! #                                   bob_encrypted_shares[1].clone(),
//! #                                   carol_encrypted_shares[1].clone());
//! # let claire_my_encrypted_secret_shares = vec!(alice_encrypted_shares[2].clone(),
//! #                                   bob_encrypted_shares[2].clone(),
//! #                                   carol_encrypted_shares[2].clone());
//! # let david_my_encrypted_secret_shares = vec!(alice_encrypted_shares[3].clone(),
//! #                                   bob_encrypted_shares[3].clone(),
//! #                                   carol_encrypted_shares[3].clone());
//! #
//! let alexis_state = alexis_state.to_round_two(alexis_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! let barbara_state = barbara_state.to_round_two(barbara_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! let claire_state = claire_state.to_round_two(claire_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! let david_state = david_state.to_round_two(david_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alexis, Barbara, Claire and David, can now use the encrypted secret
//! shares of the previous dealers to recompute the group's public key
//! and obtain their own long-lived, personal secret keys.
//!
//! ```rust
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish().or(Err(()))?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish().or(Err(()))?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish().or(Err(()))?;
//! #
//! # assert!(alice_group_key == bob_group_key);
//! # assert!(carol_group_key == bob_group_key);
//! #
//! # let new_params = Parameters { t: 3, n: 4 };
//! #
//! # let (alexis, alexis_dh_sk) = Participant::new_signer(&new_params, 1, "Φ", &mut rng);
//! # let (barbara, barbara_dh_sk) = Participant::new_signer(&new_params, 2, "Φ", &mut rng);
//! # let (claire, claire_dh_sk) = Participant::new_signer(&new_params, 3, "Φ", &mut rng);
//! # let (david, david_dh_sk) = Participant::new_signer(&new_params, 4, "Φ", &mut rng);
//! #
//! # let signers: Vec<Participant> = vec!(alexis.clone(), barbara.clone(), claire.clone(), david.clone());
//! # let (alice_as_dealer, alice_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, alice_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//! # let (bob_as_dealer, bob_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, bob_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//! # let (carol_as_dealer, carol_encrypted_shares, participant_lists) =
//! #     Participant::reshare(&new_params, carol_secret_key, &signers, "Φ", &mut rng).or(Err(()))?;
//! #
//! # let dealers: Vec<Participant> = vec!(alice_as_dealer.clone(), bob_as_dealer.clone(), carol_as_dealer.clone());
//! # let (alexis_state, participant_lists) = DistributedKeyGeneration::<_>::new(&params, &alexis_dh_sk, &alexis.index,
//! #                                                    &dealers, "Φ", &mut rng).or(Err(()))?;
//! #
//! # let (barbara_state, participant_lists) = DistributedKeyGeneration::<_>::new(&params, &barbara_dh_sk, &barbara.index,
//! #                                                    &dealers, "Φ", &mut rng).or(Err(()))?;
//! #
//! # let (claire_state, participant_lists) = DistributedKeyGeneration::<_>::new(&params, &claire_dh_sk, &claire.index,
//! #                                                      &dealers, "Φ", &mut rng).or(Err(()))?;
//! #
//! # let (david_state, participant_lists) = DistributedKeyGeneration::<_>::new(&params, &david_dh_sk, &david.index,
//! #                                                      &dealers, "Φ", &mut rng).or(Err(()))?;
//! #
//! # let alexis_my_encrypted_secret_shares = vec!(alice_encrypted_shares[0].clone(),
//! #                                   bob_encrypted_shares[0].clone(),
//! #                                   carol_encrypted_shares[0].clone());
//! # let barbara_my_encrypted_secret_shares = vec!(alice_encrypted_shares[1].clone(),
//! #                                   bob_encrypted_shares[1].clone(),
//! #                                   carol_encrypted_shares[1].clone());
//! # let claire_my_encrypted_secret_shares = vec!(alice_encrypted_shares[2].clone(),
//! #                                   bob_encrypted_shares[2].clone(),
//! #                                   carol_encrypted_shares[2].clone());
//! # let david_my_encrypted_secret_shares = vec!(alice_encrypted_shares[3].clone(),
//! #                                   bob_encrypted_shares[3].clone(),
//! #                                   carol_encrypted_shares[3].clone());
//! #
//! # let alexis_state = alexis_state.to_round_two(alexis_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let barbara_state = barbara_state.to_round_two(barbara_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let claire_state = claire_state.to_round_two(claire_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let david_state = david_state.to_round_two(david_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! #
//! let (alexis_group_key, alexis_secret_key) = alexis_state.finish().or(Err(()))?;
//! let (barbara_group_key, barbara_secret_key) = barbara_state.finish().or(Err(()))?;
//! let (claire_group_key, claire_secret_key) = claire_state.finish().or(Err(()))?;
//! let (david_group_key, david_secret_key) = david_state.finish().or(Err(()))?;
//!
//! assert!(alexis_group_key == alice_group_key);
//! assert!(barbara_group_key == alice_group_key);
//! assert!(claire_group_key == alice_group_key);
//! assert!(david_group_key == alice_group_key);
//! # Ok(()) } fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! ## Precomputation and Partial Signatures
//!
//! After running their DKG, or after receiving secret shares from a previous set of signers,
//! Alice, Bob, and Carol can now create partial threshold signatures over an agreed upon
//! message with their respective secret keys, which they can then give to an untrusted
//! [`SignatureAggregator`] (which can be one of the participants) to create a
//! 2-out-of-3 threshold signature.  To do this, they each pre-compute (using
//! [`generate_commitment_share_lists`]) and publish a list of commitment shares.
//!
//! ```rust
//! use ice_frost::compute_message_hash;
//! use ice_frost::generate_commitment_share_lists;
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! use ice_frost::SignatureAggregator;
//!
//! use rand::rngs::OsRng;
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish().or(Err(()))?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish().or(Err(()))?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish().or(Err(()))?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//!
//! let (alice_public_comshares, mut alice_secret_comshares) =
//!     generate_commitment_share_lists(&mut OsRng, 1, 1);
//! let (bob_public_comshares, mut bob_secret_comshares) =
//!     generate_commitment_share_lists(&mut OsRng, 2, 1);
//! let (carol_public_comshares, mut carol_secret_comshares) =
//!     generate_commitment_share_lists(&mut OsRng, 3, 1);
//!
//! // Each application developer should choose a context string as unique
//! // to their usage as possible, in order to provide domain separation
//! // from other applications which use FROST signatures.
//! let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! let message = b"This is a test of the tsunami alert system. This is only a test.";
//!
//! // Every signer should compute a hash of the message to be signed, along with, optionally,
//! // some additional context, such as public information about the run of the protocol.
//! let message_hash = compute_message_hash(&context[..], &message[..]);
//!
//! // The aggregator can be anyone who knows the group key, not necessarily Bob or a group participant
//! let mut aggregator =
//!     SignatureAggregator::new(
//!         params,
//!         bob_group_key.clone(),
//!         &context[..],
//!         &message[..],
//!     );
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! The aggregator takes note of each expected signer for this run of the protocol.  For this run,
//! we'll have Alice and Carol sign.
//!
//! ```rust
//! # use ice_frost::compute_message_hash;
//! # use ice_frost::generate_commitment_share_lists;
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::IndividualPublicKey;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use ice_frost::SignatureAggregator;
//! #
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish().or(Err(()))?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish().or(Err(()))?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish().or(Err(()))?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//! #
//! # let (alice_public_comshares, mut alice_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
//! # let (bob_public_comshares, mut bob_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
//! # let (carol_public_comshares, mut carol_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
//! #
//! # let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let message_hash = compute_message_hash(&context[..], &message[..]);
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &context[..], &message[..]);
//! #
//! aggregator.include_signer(1, alice_public_comshares.commitments[0], alice_public_key);
//! aggregator.include_signer(3, carol_public_comshares.commitments[0], carol_public_key);
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! The aggregator should then publicly announce which participants are expected to be signers.
//!
//! ```rust
//! # use ice_frost::compute_message_hash;
//! # use ice_frost::generate_commitment_share_lists;
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::IndividualPublicKey;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use ice_frost::SignatureAggregator;
//! #
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), ()> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(()))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(()))?;;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(()))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(()))?;;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng).or(Err(()))?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish().or(Err(()))?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish().or(Err(()))?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish().or(Err(()))?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//! #
//! # let (alice_public_comshares, mut alice_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
//! # let (bob_public_comshares, mut bob_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
//! # let (carol_public_comshares, mut carol_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
//! #
//! # let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let message_hash = compute_message_hash(&context[..], &message[..]);
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &context[..], &message[..]);
//! #
//! # aggregator.include_signer(1, alice_public_comshares.commitments[0], alice_public_key);
//! # aggregator.include_signer(3, carol_public_comshares.commitments[0], carol_public_key);
//! let signers = aggregator.get_signers();
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! Alice and Carol each then compute their partial signatures, and send these to the signature aggregator.
//!
//! ```rust
//! # use ice_frost::compute_message_hash;
//! # use ice_frost::generate_commitment_share_lists;
//! # use ice_frost::DistributedKeyGeneration;
//! # use ice_frost::Parameters;
//! # use ice_frost::Participant;
//! # use curve25519_dalek::ristretto::RistrettoPoint;
//! # use curve25519_dalek::traits::Identity;
//! # use curve25519_dalek::scalar::Scalar;
//! # use ice_frost::SignatureAggregator;
//! #
//! # use rand::rngs::OsRng;
//! #
//! # fn do_test() -> Result<(), &'static str> {
//! # let params = Parameters { t: 2, n: 3 };
//! # let mut rng = OsRng;
//! #
//! # let (alice, alice_coefficients, alice_dh_sk) = Participant::new_dealer(&params, 1, "Φ", &mut rng);
//! # let (bob, bob_coefficients, bob_dh_sk) = Participant::new_dealer(&params, 2, "Φ", &mut rng);
//! # let (carol, carol_coefficients, carol_dh_sk) = Participant::new_dealer(&params, 3, "Φ", &mut rng);
//! #
//! # let participants: Vec<Participant> = vec!(alice.clone(), bob.clone(), carol.clone());
//! # let (alice_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &alice_dh_sk, &alice.index, &alice_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(""))?;
//! # let alice_their_encrypted_secret_shares = alice_state.their_encrypted_secret_shares().or(Err(""))?;
//! #
//! # let (bob_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &bob_dh_sk, &bob.index, &bob_coefficients,
//! #                                                    &participants, "Φ", &mut rng).or(Err(""))?;
//! # let bob_their_encrypted_secret_shares = bob_state.their_encrypted_secret_shares().or(Err(""))?;
//! #
//! # let (carol_state, participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params, &carol_dh_sk, &carol.index, &carol_coefficients,
//! #                                                      &participants, "Φ", &mut rng).or(Err(""))?;
//! # let carol_their_encrypted_secret_shares = carol_state.their_encrypted_secret_shares().or(Err(""))?;
//! # let alice_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[0].clone(),
//! #                                   bob_their_encrypted_secret_shares[0].clone(),
//! #                                   carol_their_encrypted_secret_shares[0].clone());
//! # let bob_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[1].clone(),
//! #                                 bob_their_encrypted_secret_shares[1].clone(),
//! #                                 carol_their_encrypted_secret_shares[1].clone());
//! # let carol_my_encrypted_secret_shares = vec!(alice_their_encrypted_secret_shares[2].clone(),
//! #                                   bob_their_encrypted_secret_shares[2].clone(),
//! #                                   carol_their_encrypted_secret_shares[2].clone());
//! #
//! # let alice_state = alice_state.to_round_two(alice_my_encrypted_secret_shares, &mut rng).or(Err(""))?;
//! # let bob_state = bob_state.to_round_two(bob_my_encrypted_secret_shares, &mut rng).or(Err(""))?;
//! # let carol_state = carol_state.to_round_two(carol_my_encrypted_secret_shares, &mut rng).or(Err(""))?;
//! #
//! # let (alice_group_key, alice_secret_key) = alice_state.finish().or(Err(""))?;
//! # let (bob_group_key, bob_secret_key) = bob_state.finish().or(Err(""))?;
//! # let (carol_group_key, carol_secret_key) = carol_state.finish().or(Err(""))?;
//! #
//! # let alice_public_key = alice_secret_key.to_public();
//! # let bob_public_key = bob_secret_key.to_public();
//! # let carol_public_key = carol_secret_key.to_public();
//! #
//! # let (alice_public_comshares, mut alice_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
//! # let (bob_public_comshares, mut bob_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 2, 1);
//! # let (carol_public_comshares, mut carol_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);
//! #
//! # let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
//! # let message = b"This is a test of the tsunami alert system. This is only a test.";
//! #
//! # let message_hash = compute_message_hash(&context[..], &message[..]);
//! #
//! # let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &context[..], &message[..]);
//! #
//! # aggregator.include_signer(1, alice_public_comshares.commitments[0], (&alice_secret_key).into());
//! # aggregator.include_signer(3, carol_public_comshares.commitments[0], (&carol_secret_key).into());
//! #
//! # let signers = aggregator.get_signers();
//!
//! let alice_partial = alice_secret_key.sign(&message_hash, &alice_group_key,
//!                                           &mut alice_secret_comshares, 0, signers).or(Err(""))?;
//! let carol_partial = carol_secret_key.sign(&message_hash, &carol_group_key,
//!                                           &mut carol_secret_comshares, 0, signers).or(Err(""))?;
//!
//! aggregator.include_partial_signature(alice_partial);
//! aggregator.include_partial_signature(carol_partial);
//! # Ok(()) }
//! # fn main() { assert!(do_test().is_ok()); }
//! ```
//!
//! ## Signature Aggregation
//!
//! Once all the expected signers have sent their partial signatures, the
//! aggregator attempts to finalize its state, ensuring that there are no errors
//! thus far in the partial signatures, before finally attempting to complete
//! the aggregation of the partial signatures into a threshold signature.
//!
//! ```rust,ignore
//! let aggregator = aggregator.finalize()?;
//! ```
//!
//! If the aggregator could not finalize the state, then the `.finalize()` method
//! will return a `BTreeMap<u32, &'static str>` describing participant indices and the issues
//! encountered for them.  These issues are **guaranteed to be the fault of the aggregator**,
//! e.g. not collecting all the expected partial signatures, accepting two partial
//! signatures from the same participant, etc.
//!
//! And the same for the actual aggregation, if there was an error then a
//! `BTreeMap<u32, &'static str>` will be returned which maps participant indices to issues.
//! Unlike before, however, these issues are guaranteed to be the fault of the
//! corresponding participant, specifically, that their partial signature was invalid.
//!
//! ```rust,ignore
//! let threshold_signature = aggregator.aggregate()?;
//! ```
//!
//! Anyone with the group public key can then verify the threshold signature
//! in the same way they would for a standard Schnorr signature.
//!
//! ```rust,ignore
//! let verified = threshold_signature.verify(&alice_group_key, &message_hash)?;
//! ```

#![no_std]
#![warn(future_incompatible)]
#![deny(missing_docs)]
#![allow(non_snake_case)]

#[cfg(not(any(feature = "std", feature = "alloc")))]
compile_error!("Either feature \"std\" or \"alloc\" must be enabled for this crate.");

// We use the vec! macro in unittests.
#[cfg(any(test, feature = "std"))]
#[macro_use]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod keygen;
pub mod nizk;
pub mod parameters;
pub mod precomputation;
pub mod signature;

pub use keygen::Error;

pub use keygen::DistributedKeyGeneration;
pub use keygen::GroupKey;
pub use keygen::IndividualPublicKey;
pub use keygen::Participant;
pub use keygen::SecretKey as IndividualSecretKey;
pub use parameters::Parameters;
pub use precomputation::generate_commitment_share_lists;

pub use signature::compute_message_hash;
pub use signature::SignatureAggregator;
