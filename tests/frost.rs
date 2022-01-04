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

//! Integration tests for FROST.

use ed25519_dalek::Verifier;

use rand::rngs::OsRng;

use ice_frost::compute_message_hash;
use ice_frost::generate_commitment_share_lists;

use ice_frost::DistributedKeyGeneration;
use ice_frost::Parameters;
use ice_frost::Participant;

use ice_frost::SignatureAggregator;

#[test]
fn signing_and_verification_3_out_of_5() {
    let params = Parameters { n: 5, t: 3 };

    let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ");
    let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, "Φ");
    let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, "Φ");
    let (p4, p4coeffs, p4_dh_sk) = Participant::new_dealer(&params, 4, "Φ");
    let (p5, p5coeffs, p5_dh_sk) = Participant::new_dealer(&params, 5, "Φ");

    let participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone(), p4.clone(), p5.clone());
    let (p1_state, _participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params,
                                                             &p1_dh_sk,
                                                             &p1.index,
                                                             &p1coeffs,
                                                             &participants,
                                                             "Φ").unwrap();
    let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap();

    let (p2_state, _participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params,
                                                             &p2_dh_sk,
                                                             &p2.index,
                                                             &p2coeffs,
                                                             &participants,
                                                             "Φ").unwrap();
    let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

    let (p3_state, _participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params,
                                                             &p3_dh_sk,
                                                             &p3.index,
                                                             &p3coeffs,
                                                             &participants,
                                                             "Φ").unwrap();
    let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares().unwrap();

    let (p4_state, _participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params,
                                                             &p4_dh_sk,
                                                             &p4.index,
                                                             &p4coeffs,
                                                             &participants,
                                                             "Φ").unwrap();
    let p4_their_encrypted_secret_shares = p4_state.their_encrypted_secret_shares().unwrap();

    let (p5_state, _participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params,
                                                             &p5_dh_sk,
                                                             &p5.index,
                                                             &p5coeffs,
                                                             &participants,
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

/// We are currently incompatible with ed25519 verification.
#[test]
fn signing_and_verification_with_ed25519_dalek_2_out_of_3() {
    let params = Parameters { n: 3, t: 2 };

    let (p1, p1coeffs, p1_dh_sk) = Participant::new_dealer(&params, 1, "Φ");
    let (p2, p2coeffs, p2_dh_sk) = Participant::new_dealer(&params, 2, "Φ");
    let (p3, p3coeffs, p3_dh_sk) = Participant::new_dealer(&params, 3, "Φ");

    let participants: Vec<Participant> = vec!(p1.clone(), p2.clone(), p3.clone());
    let (p1_state, _participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params,
                                                      &p1_dh_sk,
                                                      &p1.index,
                                                      &p1coeffs,
                                                      &participants,
                                                      "Φ").unwrap();
    let p1_their_encrypted_secret_shares = p1_state.their_encrypted_secret_shares().unwrap();

    let (p2_state, _participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params,
                                                     &p2_dh_sk,
                                                     &p2.index,
                                                     &p2coeffs,
                                                     &participants,
                                                     "Φ").unwrap();
    let p2_their_encrypted_secret_shares = p2_state.their_encrypted_secret_shares().unwrap();

    let (p3_state, _participant_lists) = DistributedKeyGeneration::<_>::new_initial(&params,
                                                      &p3_dh_sk,
                                                      &p3.index,
                                                      &p3coeffs,
                                                      &participants,
                                                      "Φ").unwrap();
    let p3_their_encrypted_secret_shares = p3_state.their_encrypted_secret_shares().unwrap();

    let p1_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[0].clone(),
                                   p2_their_encrypted_secret_shares[0].clone(),
                                   p3_their_encrypted_secret_shares[0].clone());

    let p2_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[1].clone(),
                                   p2_their_encrypted_secret_shares[1].clone(),
                                   p3_their_encrypted_secret_shares[1].clone());

    let p3_my_encrypted_secret_shares = vec!(p1_their_encrypted_secret_shares[2].clone(),
                                   p2_their_encrypted_secret_shares[2].clone(),
                                   p3_their_encrypted_secret_shares[2].clone());

    let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).unwrap();
    let p2_state = p2_state.to_round_two(p2_my_encrypted_secret_shares).unwrap();
    let p3_state = p3_state.to_round_two(p3_my_encrypted_secret_shares).unwrap();

    let (group_key, p1_sk) = p1_state.finish().unwrap();
    let (_, p2_sk) = p2_state.finish().unwrap();
    let (_, p3_sk) = p3_state.finish().unwrap();

    let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
    let message = b"This is a test of the tsunami alert system. This is only a test.";
    let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
    let (p3_public_comshares, mut p3_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 3, 1);

    let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

    aggregator.include_signer(1, p1_public_comshares.commitments[0], (&p1_sk).into());
    aggregator.include_signer(3, p3_public_comshares.commitments[0], (&p3_sk).into());

    let signers = aggregator.get_signers();
    let message_hash = compute_message_hash(&context[..], &message[..]);

    let p1_partial = p1_sk.sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers).unwrap();
    let p3_partial = p3_sk.sign(&message_hash, &group_key, &mut p3_secret_comshares, 0, signers).unwrap();

    aggregator.include_partial_signature(p1_partial);
    aggregator.include_partial_signature(p3_partial);

    let aggregator = aggregator.finalize().unwrap();
    let threshold_signature = aggregator.aggregate().unwrap();
    let verification_result = threshold_signature.verify(&group_key, &message_hash);

    assert!(verification_result.is_ok());

    let signature_bytes = threshold_signature.to_bytes();
    let signature = ed25519_dalek::Signature::from(signature_bytes);

    let public_key_bytes = group_key.to_bytes();
    let public_key = ed25519_dalek::PublicKey::from_bytes(&public_key_bytes[..]);

    if public_key.is_ok() {
        let pk = public_key.unwrap();
        println!("Verifying signature");
        let verified = pk.verify(&message_hash[..], &signature).is_ok();

        if verified {
            println!("Public key was okay? {:?}", pk.to_bytes());
            println!("Signature checked out? {:?}", signature_bytes);
            println!("p1 secret key: {:?}", p1_sk);
            println!("p2 secret key: {:?}", p2_sk);
            println!("p3 secret key: {:?}", p3_sk);
            println!("p1 secret commitment shares: {:?}", p1_secret_comshares);
            println!("p3 secret commitment shares: {:?}", p3_secret_comshares);
            assert!(false);
        }
    }
}
