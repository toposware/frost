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

//! Benchmarks for FROST.

#[macro_use]
extern crate criterion;

use criterion::Criterion;

use rand::rngs::OsRng;

use ice_frost::compute_message_hash;
use ice_frost::generate_commitment_share_lists;
use ice_frost::keygen::{
    Coefficients,
    DHPrivateKey,
    EncryptedSecretShare,
};
use ice_frost::DistributedKeyGeneration;
use ice_frost::IndividualSecretKey;
use ice_frost::Parameters;
use ice_frost::Participant;
use ice_frost::precomputation::{
    PublicCommitmentShareList,
    SecretCommitmentShareList,
};
use ice_frost::SignatureAggregator;

const NUMBER_OF_PARTICIPANTS: u32 = 5;
const THRESHOLD_OF_PARTICIPANTS: u32 = 3;

mod dkg_benches {
    use super::*;

    fn participant_new(c: &mut Criterion) {
        let params = Parameters { n: NUMBER_OF_PARTICIPANTS, t: THRESHOLD_OF_PARTICIPANTS };
        c.bench_function("Participant creation", move |b| b.iter(|| Participant::new(&params, 1, "Φ")));
    }

    fn round_one_t_out_of_n(c: &mut Criterion) {
        let params = Parameters { n: NUMBER_OF_PARTICIPANTS, t: THRESHOLD_OF_PARTICIPANTS };

        let mut participants_except_p1 = Vec::<Participant>::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize);
        let (p1, coefficient, p1_dh_sk) = Participant::new(&params, 1, "Φ");

        for i in 2..NUMBER_OF_PARTICIPANTS+1 {
            let (p, _, _) = Participant::new(&params, i, "Φ");
            participants_except_p1.push(p);
        }

        c.bench_function("Round One", move |b| {
            b.iter(|| DistributedKeyGeneration::<_>::new(&params,
                                                         &p1_dh_sk,
                                                         &p1.index,
                                                         &coefficient,
                                                         &mut participants_except_p1,
                                                         "Φ"));
        });
    }

    fn round_two_t_out_of_n(c: &mut Criterion) {
        let params = Parameters { n: NUMBER_OF_PARTICIPANTS, t: THRESHOLD_OF_PARTICIPANTS };

        let mut participants = Vec::<Participant>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut coefficients = Vec::<Coefficients>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut dh_secret_keys = Vec::<DHPrivateKey>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

        for i in 1..NUMBER_OF_PARTICIPANTS+1 {
            let (p, c, dh_sk) = Participant::new(&params, i, "Φ");
            participants.push(p);
            coefficients.push(c);
            dh_secret_keys.push(dh_sk);
        }

        let mut p1_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize);

        let mut participants_except_p1: Vec::<Participant> = participants.clone();
        participants_except_p1.remove(0);
        let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &dh_secret_keys[0],
                                                          &participants[0].index,
                                                          &coefficients[0],
                                                          &mut participants_except_p1,
                                                          "Φ").unwrap();

        for i in 2..NUMBER_OF_PARTICIPANTS+1 {
            let mut participants_except_pi: Vec::<Participant> = participants.clone();
            participants_except_pi.remove((i-1) as usize);
            let pi_state = DistributedKeyGeneration::<_>::new(&params,
                                                              &dh_secret_keys[(i-1) as usize],
                                                              &participants[(i-1) as usize].index,
                                                              &coefficients[(i-1) as usize],
                                                              &mut participants_except_pi,
                                                              "Φ").unwrap();
            let pi_their_encrypted_secret_shares = pi_state.their_encrypted_secret_shares().unwrap();
            p1_my_encrypted_secret_shares.push(pi_their_encrypted_secret_shares[0].clone());
        }

        c.bench_function("Round Two", move |b| {
            b.iter(|| p1_state.clone().to_round_two(p1_my_encrypted_secret_shares.clone()));
        });
    }

    fn finish_t_out_of_n(c: &mut Criterion) {
        let params = Parameters { n: NUMBER_OF_PARTICIPANTS, t: THRESHOLD_OF_PARTICIPANTS };

        let mut participants = Vec::<Participant>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut coefficients = Vec::<Coefficients>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut dh_secret_keys = Vec::<DHPrivateKey>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

        for i in 1..NUMBER_OF_PARTICIPANTS+1 {
            let (p, c, dh_sk) = Participant::new(&params, i, "Φ");
            participants.push(p);
            coefficients.push(c);
            dh_secret_keys.push(dh_sk);
        }

        let mut p1_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize);

        let mut participants_except_p1: Vec::<Participant> = participants.clone();
        participants_except_p1.remove(0);
        let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &dh_secret_keys[0],
                                                          &participants[0].index,
                                                          &coefficients[0],
                                                          &mut participants_except_p1,
                                                          "Φ").unwrap();

        for i in 2..NUMBER_OF_PARTICIPANTS+1 {
            let mut participants_except_pi: Vec::<Participant> = participants.clone();
            participants_except_pi.remove((i-1) as usize);
            let pi_state = DistributedKeyGeneration::<_>::new(&params,
                                                              &dh_secret_keys[(i-1) as usize],
                                                              &participants[(i-1) as usize].index,
                                                              &coefficients[(i-1) as usize],
                                                              &mut participants_except_pi,
                                                              "Φ").unwrap();
            let pi_their_encrypted_secret_shares = pi_state.their_encrypted_secret_shares().unwrap();
            p1_my_encrypted_secret_shares.push(pi_their_encrypted_secret_shares[0].clone());
        }

        let p1_state = p1_state.to_round_two(p1_my_encrypted_secret_shares).unwrap();

        c.bench_function("Finish", move |b| {
            let comm = &participants[0].commitments.points;

            b.iter(|| p1_state.clone().finish(comm.clone()));
        });
    }

    criterion_group! {
        name = dkg_benches;
        config = Criterion::default().sample_size(10);
        targets =
            participant_new,
            round_one_t_out_of_n,
            round_two_t_out_of_n,
            finish_t_out_of_n,
    }
}

mod sign_benches {
    use super::*;

    fn partial_sign_t_out_of_n(c: &mut Criterion) {
        let params = Parameters { n: NUMBER_OF_PARTICIPANTS, t: THRESHOLD_OF_PARTICIPANTS };

        let mut participants = Vec::<Participant>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut coefficients = Vec::<Coefficients>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut dh_secret_keys = Vec::<DHPrivateKey>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

        for i in 1..NUMBER_OF_PARTICIPANTS+1 {
            let (p, c, dh_sk) = Participant::new(&params, i, "Φ");
            participants.push(p);
            coefficients.push(c);
            dh_secret_keys.push(dh_sk);
        }

        let mut participants_encrypted_secret_shares: Vec<Vec::<EncryptedSecretShare>> = 
                (0..NUMBER_OF_PARTICIPANTS).map(|_| Vec::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize)).collect();

        let mut participants_states_1 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut participants_states_2 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

        for i in 1..NUMBER_OF_PARTICIPANTS+1 {
            let mut participants_except_pi: Vec::<Participant> = participants.clone();
            participants_except_pi.remove((i-1) as usize);
            let pi_state = DistributedKeyGeneration::<_>::new(&params,
                                                              &dh_secret_keys[(i-1) as usize],
                                                              &participants[(i-1) as usize].index,
                                                              &coefficients[(i-1) as usize],
                                                              &mut participants_except_pi,
                                                              "Φ").unwrap();
            let pi_their_encrypted_secret_shares = pi_state.their_encrypted_secret_shares().unwrap();
            participants_encrypted_secret_shares[(i-1) as usize] = pi_their_encrypted_secret_shares.clone();
            participants_states_1.push(pi_state);
        }

        let mut p1_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize);
        for j in 2..NUMBER_OF_PARTICIPANTS+1 {
            p1_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][0].clone());
        }
        participants_states_2.push(participants_states_1[0].clone().to_round_two(p1_my_encrypted_secret_shares).unwrap());

        for i in 2..NUMBER_OF_PARTICIPANTS+1 {
            let mut pi_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize);
            let mut increment = -1i32;
            for j in 1..i {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][((i-j) as i32 + increment) as usize].clone());
                increment += 1;
            }
            for j in (i+1)..NUMBER_OF_PARTICIPANTS+1 {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][(i-1) as usize].clone());
            }

            participants_states_2.push(participants_states_1[(i-1) as usize].clone().to_round_two(pi_my_encrypted_secret_shares).unwrap());
        }

        let mut participants_secret_keys = Vec::<IndividualSecretKey>::with_capacity(THRESHOLD_OF_PARTICIPANTS as usize);
        let (group_key, p1_sk) = participants_states_2[0].clone().finish(participants[1].clone().commitments.points).unwrap();
        participants_secret_keys.push(p1_sk);

        for i in 2..THRESHOLD_OF_PARTICIPANTS+1 {
            let (_, pi_sk) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].clone().commitments.points).unwrap();
            participants_secret_keys.push(pi_sk);
        }
        for i in (THRESHOLD_OF_PARTICIPANTS+2)..NUMBER_OF_PARTICIPANTS+1 {
            let (_, _) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].clone().commitments.points).unwrap();
        }

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let mut participants_public_comshares = Vec::<PublicCommitmentShareList>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        participants_public_comshares.push(p1_public_comshares);

        for i in 2..NUMBER_OF_PARTICIPANTS+1 {
            let (pi_public_comshares, _pi_secret_comshares) = generate_commitment_share_lists(&mut OsRng, i, 1);
            participants_public_comshares.push(pi_public_comshares);
        }

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        for i in 1..THRESHOLD_OF_PARTICIPANTS+1 {
            aggregator.include_signer(i, participants_public_comshares[(i-1) as usize].commitments[0], (&participants_secret_keys[(i-1) as usize]).into());
        }

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        c.bench_function("Partial signature creation", move |b| {
            b.iter(|| participants_secret_keys[0].sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers));
        });
    }

    fn signature_aggregation_t_out_of_n(c: &mut Criterion) {
        let params = Parameters { n: NUMBER_OF_PARTICIPANTS, t: THRESHOLD_OF_PARTICIPANTS };

        let mut participants = Vec::<Participant>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut coefficients = Vec::<Coefficients>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut dh_secret_keys = Vec::<DHPrivateKey>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

        for i in 1..NUMBER_OF_PARTICIPANTS+1 {
            let (p, c, dh_sk) = Participant::new(&params, i, "Φ");
            participants.push(p);
            coefficients.push(c);
            dh_secret_keys.push(dh_sk);
        }

        let mut participants_encrypted_secret_shares: Vec<Vec::<EncryptedSecretShare>> = 
                (0..NUMBER_OF_PARTICIPANTS).map(|_| Vec::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize)).collect();

        let mut participants_states_1 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut participants_states_2 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

        for i in 1..NUMBER_OF_PARTICIPANTS+1 {
            let mut participants_except_pi: Vec::<Participant> = participants.clone();
            participants_except_pi.remove((i-1) as usize);
            let pi_state = DistributedKeyGeneration::<_>::new(&params,
                                                              &dh_secret_keys[(i-1) as usize],
                                                              &participants[(i-1) as usize].index,
                                                              &coefficients[(i-1) as usize],
                                                              &mut participants_except_pi,
                                                              "Φ").unwrap();
            let pi_their_encrypted_secret_shares = pi_state.their_encrypted_secret_shares().unwrap();
            participants_encrypted_secret_shares[(i-1) as usize] = pi_their_encrypted_secret_shares.clone();
            participants_states_1.push(pi_state);
        }

        let mut p1_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize);
        for j in 2..NUMBER_OF_PARTICIPANTS+1 {
            p1_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][0].clone());
        }
        participants_states_2.push(participants_states_1[0].clone().to_round_two(p1_my_encrypted_secret_shares).unwrap());

        for i in 2..NUMBER_OF_PARTICIPANTS+1 {
            let mut pi_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize);
            let mut increment = -1i32;
            for j in 1..i {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][((i-j) as i32 + increment) as usize].clone());
                increment += 1;
            }
            for j in (i+1)..NUMBER_OF_PARTICIPANTS+1 {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][(i-1) as usize].clone());
            }

            participants_states_2.push(participants_states_1[(i-1) as usize].clone().to_round_two(pi_my_encrypted_secret_shares).unwrap());
        }

        let mut participants_secret_keys = Vec::<IndividualSecretKey>::with_capacity(THRESHOLD_OF_PARTICIPANTS as usize);
        let (group_key, p1_sk) = participants_states_2[0].clone().finish(participants[1].clone().commitments.points).unwrap();
        participants_secret_keys.push(p1_sk);

        for i in 2..THRESHOLD_OF_PARTICIPANTS+1 {
            let (_, pi_sk) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].clone().commitments.points).unwrap();
            participants_secret_keys.push(pi_sk);
        }
        for i in (THRESHOLD_OF_PARTICIPANTS+2)..NUMBER_OF_PARTICIPANTS+1 {
            let (_, _) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].clone().commitments.points).unwrap();
        }

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let mut participants_public_comshares = Vec::<PublicCommitmentShareList>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut participants_secret_comshares = Vec::<SecretCommitmentShareList>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let (p1_public_comshares, p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        participants_public_comshares.push(p1_public_comshares);
        participants_secret_comshares.push(p1_secret_comshares);

        for i in 2..NUMBER_OF_PARTICIPANTS+1 {
            let (pi_public_comshares, pi_secret_comshares) = generate_commitment_share_lists(&mut OsRng, i, 1);
            participants_public_comshares.push(pi_public_comshares);
            participants_secret_comshares.push(pi_secret_comshares);
        }

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        for i in 1..THRESHOLD_OF_PARTICIPANTS+1 {
            aggregator.include_signer(i, participants_public_comshares[(i-1) as usize].commitments[0], (&participants_secret_keys[(i-1) as usize]).into());
        }

        let signers = aggregator.get_signers().clone();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        for i in 1..THRESHOLD_OF_PARTICIPANTS+1 {
            let pi_partial_signature = participants_secret_keys[(i-1) as usize].sign(&message_hash, &group_key, &mut participants_secret_comshares[(i-1) as usize], 0, &signers).unwrap();
            aggregator.include_partial_signature(pi_partial_signature);
        }

        let aggregator = aggregator.finalize().unwrap();

        c.bench_function("Signature aggregation", move |b| {
            b.iter(|| aggregator.aggregate());
        });
    }

    fn verify_t_out_of_n(c: &mut Criterion) {
        let params = Parameters { n: NUMBER_OF_PARTICIPANTS, t: THRESHOLD_OF_PARTICIPANTS };

        let mut participants = Vec::<Participant>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut coefficients = Vec::<Coefficients>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut dh_secret_keys = Vec::<DHPrivateKey>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

        for i in 1..NUMBER_OF_PARTICIPANTS+1 {
            let (p, c, dh_sk) = Participant::new(&params, i, "Φ");
            participants.push(p);
            coefficients.push(c);
            dh_secret_keys.push(dh_sk);
        }

        let mut participants_encrypted_secret_shares: Vec<Vec::<EncryptedSecretShare>> = 
                (0..NUMBER_OF_PARTICIPANTS).map(|_| Vec::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize)).collect();

        let mut participants_states_1 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut participants_states_2 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);

        for i in 1..NUMBER_OF_PARTICIPANTS+1 {
            let mut participants_except_pi: Vec::<Participant> = participants.clone();
            participants_except_pi.remove((i-1) as usize);
            let pi_state = DistributedKeyGeneration::<_>::new(&params,
                                                              &dh_secret_keys[(i-1) as usize],
                                                              &participants[(i-1) as usize].index,
                                                              &coefficients[(i-1) as usize],
                                                              &mut participants_except_pi,
                                                              "Φ").unwrap();
            let pi_their_encrypted_secret_shares = pi_state.their_encrypted_secret_shares().unwrap();
            participants_encrypted_secret_shares[(i-1) as usize] = pi_their_encrypted_secret_shares.clone();
            participants_states_1.push(pi_state);
        }

        let mut p1_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize);
        for j in 2..NUMBER_OF_PARTICIPANTS+1 {
            p1_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][0].clone());
        }
        participants_states_2.push(participants_states_1[0].clone().to_round_two(p1_my_encrypted_secret_shares).unwrap());

        for i in 2..NUMBER_OF_PARTICIPANTS+1 {
            let mut pi_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((NUMBER_OF_PARTICIPANTS - 1) as usize);
            let mut increment = -1i32;
            for j in 1..i {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][((i-j) as i32 + increment) as usize].clone());
                increment += 1;
            }
            for j in (i+1)..NUMBER_OF_PARTICIPANTS+1 {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][(i-1) as usize].clone());
            }

            participants_states_2.push(participants_states_1[(i-1) as usize].clone().to_round_two(pi_my_encrypted_secret_shares).unwrap());
        }

        let mut participants_secret_keys = Vec::<IndividualSecretKey>::with_capacity(THRESHOLD_OF_PARTICIPANTS as usize);
        let (group_key, p1_sk) = participants_states_2[0].clone().finish(participants[1].clone().commitments.points).unwrap();
        participants_secret_keys.push(p1_sk);

        for i in 2..THRESHOLD_OF_PARTICIPANTS+1 {
            let (_, pi_sk) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].clone().commitments.points).unwrap();
            participants_secret_keys.push(pi_sk);
        }
        for i in (THRESHOLD_OF_PARTICIPANTS+2)..NUMBER_OF_PARTICIPANTS+1 {
            let (_, _) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].clone().commitments.points).unwrap();
        }

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let mut participants_public_comshares = Vec::<PublicCommitmentShareList>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let mut participants_secret_comshares = Vec::<SecretCommitmentShareList>::with_capacity(NUMBER_OF_PARTICIPANTS as usize);
        let (p1_public_comshares, p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        participants_public_comshares.push(p1_public_comshares);
        participants_secret_comshares.push(p1_secret_comshares);

        for i in 2..NUMBER_OF_PARTICIPANTS+1 {
            let (pi_public_comshares, pi_secret_comshares) = generate_commitment_share_lists(&mut OsRng, i, 1);
            participants_public_comshares.push(pi_public_comshares);
            participants_secret_comshares.push(pi_secret_comshares);
        }

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        for i in 1..THRESHOLD_OF_PARTICIPANTS+1 {
            aggregator.include_signer(i, participants_public_comshares[(i-1) as usize].commitments[0], (&participants_secret_keys[(i-1) as usize]).into());
        }

        let signers = aggregator.get_signers().clone();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        for i in 1..THRESHOLD_OF_PARTICIPANTS+1 {
            let pi_partial_signature = participants_secret_keys[(i-1) as usize].sign(&message_hash, &group_key, &mut participants_secret_comshares[(i-1) as usize], 0, &signers).unwrap();
            aggregator.include_partial_signature(pi_partial_signature);
        }

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();

        c.bench_function("Signature verification", move |b| {
            b.iter(|| threshold_signature.verify(&group_key, &message_hash));
        });
    }

    criterion_group! {
        name = sign_benches;
        config = Criterion::default().sample_size(10);
        targets =
            partial_sign_t_out_of_n,
            signature_aggregation_t_out_of_n,
            verify_t_out_of_n,
    }
}

criterion_main!(
    dkg_benches::dkg_benches,
    sign_benches::sign_benches,
);
