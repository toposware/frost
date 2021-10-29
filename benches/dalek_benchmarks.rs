// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>

//! Benchmarks for FROST.

#[macro_use]
extern crate criterion;

use criterion::Criterion;

use rand::rngs::OsRng;

use frost_dalek::compute_message_hash;
use frost_dalek::generate_commitment_share_lists;
use frost_dalek::keygen::{
    Coefficients,
    DHPrivateKey,
    EncryptedSecretShare,
};
use frost_dalek::DistributedKeyGeneration;
use frost_dalek::IndividualSecretKey;
use frost_dalek::Parameters;
use frost_dalek::Participant;
use frost_dalek::precomputation::{
    PublicCommitmentShareList,
    SecretCommitmentShareList,
};
use frost_dalek::SignatureAggregator;

mod dkg_benches {
    use super::*;

    fn participant_new(name: &str, n: u32, t: u32, c: &mut Criterion) {
        let params = Parameters { n, t };
        let bench_name = name.to_string() + "Participant creation";
        c.bench_function(&bench_name, move |b| b.iter(|| Participant::new(&params, 1, "Φ")));
    }

    fn round_one_t_out_of_n(name: &str, n: u32, t: u32, c: &mut Criterion) {
        let params = Parameters { n, t };

        let mut participants_except_p1 = Vec::<Participant>::with_capacity((n - 1) as usize);
        let (p1, coefficient, p1_dh_sk) = Participant::new(&params, 1, "Φ");

        for i in 2..n+1 {
            let (p, _, _) = Participant::new(&params, i, "Φ");
            participants_except_p1.push(p);
        }

        let bench_name = name.to_string() + "Round One";
        c.bench_function(&bench_name, move |b| {
            b.iter(|| DistributedKeyGeneration::<_>::new(&params,
                                                         &p1_dh_sk,
                                                         &p1.index,
                                                         &coefficient,
                                                         &mut participants_except_p1,
                                                         "Φ"));
        });
    }

    fn round_two_t_out_of_n(name: &str, n: u32, t: u32, c: &mut Criterion) {
        let params = Parameters { n, t };

        let mut participants = Vec::<Participant>::with_capacity(n as usize);
        let mut coefficients = Vec::<Coefficients>::with_capacity(n as usize);
        let mut dh_secret_keys = Vec::<DHPrivateKey>::with_capacity(n as usize);

        for i in 1..n+1 {
            let (p, c, dh_sk) = Participant::new(&params, i, "Φ");
            participants.push(p);
            coefficients.push(c);
            dh_secret_keys.push(dh_sk);
        }

        let mut p1_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((n - 1) as usize);

        let mut participants_except_p1: Vec::<Participant> = participants.clone();
        participants_except_p1.remove(0);
        let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &dh_secret_keys[0],
                                                          &participants[0].index,
                                                          &coefficients[0],
                                                          &mut participants_except_p1,
                                                          "Φ").unwrap();

        for i in 2..n+1 {
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

        let bench_name = name.to_string() + "Round Two";
        c.bench_function(&bench_name, move |b| {
            b.iter(|| p1_state.clone().to_round_two(p1_my_encrypted_secret_shares.clone()));
        });
    }

    fn finish_t_out_of_n(name: &str, n: u32, t: u32, c: &mut Criterion) {
        let params = Parameters { n, t };

        let mut participants = Vec::<Participant>::with_capacity(n as usize);
        let mut coefficients = Vec::<Coefficients>::with_capacity(n as usize);
        let mut dh_secret_keys = Vec::<DHPrivateKey>::with_capacity(n as usize);

        for i in 1..n+1 {
            let (p, c, dh_sk) = Participant::new(&params, i, "Φ");
            participants.push(p);
            coefficients.push(c);
            dh_secret_keys.push(dh_sk);
        }

        let mut p1_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((n - 1) as usize);

        let mut participants_except_p1: Vec::<Participant> = participants.clone();
        participants_except_p1.remove(0);
        let p1_state = DistributedKeyGeneration::<_>::new(&params,
                                                          &dh_secret_keys[0],
                                                          &participants[0].index,
                                                          &coefficients[0],
                                                          &mut participants_except_p1,
                                                          "Φ").unwrap();

        for i in 2..n+1 {
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

        let bench_name = name.to_string() + "Finish";
        c.bench_function(&bench_name, move |b| {
            let pk = participants[0].public_key().unwrap();

            b.iter(|| p1_state.clone().finish(pk));
        });
    }

    fn verify_zkp(c: &mut Criterion) {
        let params = Parameters { n: 3, t: 2 };
        let (p, _, _) = Participant::new(&params, 1, "Φ");

        let bench_name = "ZKP Verification";
        c.bench_function(&bench_name, move |b| {
            b.iter(|| p.proof_of_secret_key.verify(&p.index, &p.commitments[0], "Φ"));
        });
    }

    fn dkg_bench_with_t_out_of_n(n: u32, t: u32, c: &mut Criterion) {
        let name = t.to_string() + "-out-of-" + &n.to_string() + ": ";
        participant_new(&name, n, t, c);
        round_one_t_out_of_n(&name, n, t, c);
        round_two_t_out_of_n(&name, n, t, c);
        finish_t_out_of_n(&name, n, t, c);
    }

    fn dkg_bench(c: &mut Criterion) {
        verify_zkp(c);
        dkg_bench_with_t_out_of_n(100, 34, c);
        dkg_bench_with_t_out_of_n(100, 67, c);
        dkg_bench_with_t_out_of_n(200, 67, c);
        dkg_bench_with_t_out_of_n(200, 134, c);
        dkg_bench_with_t_out_of_n(300, 101, c);
        dkg_bench_with_t_out_of_n(300, 201, c);
        dkg_bench_with_t_out_of_n(500, 167, c);
        dkg_bench_with_t_out_of_n(500, 334, c);
        dkg_bench_with_t_out_of_n(1000, 334, c);
        dkg_bench_with_t_out_of_n(1000, 667, c);
    }

    criterion_group! {
        name = dkg_benches;
        config = Criterion::default().sample_size(10);
        targets = dkg_bench,
    }
}

mod sign_benches {
    use super::*;

    fn partial_sign_t_out_of_n(name: &str, n: u32, t: u32, c: &mut Criterion) {
        let params = Parameters { n, t };

        let mut participants = Vec::<Participant>::with_capacity(n as usize);
        let mut coefficients = Vec::<Coefficients>::with_capacity(n as usize);
        let mut dh_secret_keys = Vec::<DHPrivateKey>::with_capacity(n as usize);

        for i in 1..n+1 {
            let (p, c, dh_sk) = Participant::new(&params, i, "Φ");
            participants.push(p);
            coefficients.push(c);
            dh_secret_keys.push(dh_sk);
        }

        let mut participants_encrypted_secret_shares: Vec<Vec::<EncryptedSecretShare>> = 
                (0..n).map(|_| Vec::with_capacity((n - 1) as usize)).collect();
        
        let mut participants_states_1 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(n as usize);
        let mut participants_states_2 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(n as usize);

        for i in 1..n+1 {
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

        let mut p1_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((n - 1) as usize);
        for j in 2..n+1 {
            p1_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][0].clone());
        }
        participants_states_2.push(participants_states_1[0].clone().to_round_two(p1_my_encrypted_secret_shares).unwrap());

        for i in 2..n+1 {
            let mut pi_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((n - 1) as usize);
            let mut increment = -1i32;
            for j in 1..i {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][((i-j) as i32 + increment) as usize].clone());
                increment += 1;
            }
            for j in (i+1)..n+1 {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][(i-1) as usize].clone());
            }

            participants_states_2.push(participants_states_1[(i-1) as usize].clone().to_round_two(pi_my_encrypted_secret_shares).unwrap());
        }

        let mut participants_secret_keys = Vec::<IndividualSecretKey>::with_capacity(t as usize);
        let (group_key, p1_sk) = participants_states_2[0].clone().finish(participants[1].public_key().unwrap()).unwrap();
        participants_secret_keys.push(p1_sk);

        for i in 2..t+1 {
            let (_, pi_sk) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].public_key().unwrap()).unwrap();
            participants_secret_keys.push(pi_sk);
        }
        for i in (t+2)..n+1 {
            let (_, _) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].public_key().unwrap()).unwrap();
        }

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let mut participants_public_comshares = Vec::<PublicCommitmentShareList>::with_capacity(n as usize);
        let (p1_public_comshares, mut p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        participants_public_comshares.push(p1_public_comshares);

        for i in 2..n+1 {
            let (pi_public_comshares, _pi_secret_comshares) = generate_commitment_share_lists(&mut OsRng, i, 1);
            participants_public_comshares.push(pi_public_comshares);
        }

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        for i in 1..t+1 {
            aggregator.include_signer(i, participants_public_comshares[(i-1) as usize].commitments[0], (&participants_secret_keys[(i-1) as usize]).into());
        }

        let signers = aggregator.get_signers();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        let bench_name = name.to_string() + "Partial signature creation";
        c.bench_function(&bench_name, move |b| {
            b.iter(|| participants_secret_keys[0].sign(&message_hash, &group_key, &mut p1_secret_comshares, 0, signers));
        });
    }

    fn signature_aggregation_t_out_of_n(name: &str, n: u32, t: u32, c: &mut Criterion) {
        let params = Parameters { n, t };

        let mut participants = Vec::<Participant>::with_capacity(n as usize);
        let mut coefficients = Vec::<Coefficients>::with_capacity(n as usize);
        let mut dh_secret_keys = Vec::<DHPrivateKey>::with_capacity(n as usize);

        for i in 1..n+1 {
            let (p, c, dh_sk) = Participant::new(&params, i, "Φ");
            participants.push(p);
            coefficients.push(c);
            dh_secret_keys.push(dh_sk);
        }

        let mut participants_encrypted_secret_shares: Vec<Vec::<EncryptedSecretShare>> = 
                (0..n).map(|_| Vec::with_capacity((n - 1) as usize)).collect();
        
        let mut participants_states_1 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(n as usize);
        let mut participants_states_2 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(n as usize);

        for i in 1..n+1 {
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

        let mut p1_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((n - 1) as usize);
        for j in 2..n+1 {
            p1_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][0].clone());
        }
        participants_states_2.push(participants_states_1[0].clone().to_round_two(p1_my_encrypted_secret_shares).unwrap());

        for i in 2..n+1 {
            let mut pi_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((n - 1) as usize);
            let mut increment = -1i32;
            for j in 1..i {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][((i-j) as i32 + increment) as usize].clone());
                increment += 1;
            }
            for j in (i+1)..n+1 {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][(i-1) as usize].clone());
            }

            participants_states_2.push(participants_states_1[(i-1) as usize].clone().to_round_two(pi_my_encrypted_secret_shares).unwrap());
        }

        let mut participants_secret_keys = Vec::<IndividualSecretKey>::with_capacity(t as usize);
        let (group_key, p1_sk) = participants_states_2[0].clone().finish(participants[1].public_key().unwrap()).unwrap();
        participants_secret_keys.push(p1_sk);

        for i in 2..t+1 {
            let (_, pi_sk) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].public_key().unwrap()).unwrap();
            participants_secret_keys.push(pi_sk);
        }
        for i in (t+2)..n+1 {
            let (_, _) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].public_key().unwrap()).unwrap();
        }

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let mut participants_public_comshares = Vec::<PublicCommitmentShareList>::with_capacity(n as usize);
        let mut participants_secret_comshares = Vec::<SecretCommitmentShareList>::with_capacity(n as usize);
        let (p1_public_comshares, p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        participants_public_comshares.push(p1_public_comshares);
        participants_secret_comshares.push(p1_secret_comshares);

        for i in 2..n+1 {
            let (pi_public_comshares, pi_secret_comshares) = generate_commitment_share_lists(&mut OsRng, i, 1);
            participants_public_comshares.push(pi_public_comshares);
            participants_secret_comshares.push(pi_secret_comshares);
        }

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        for i in 1..t+1 {
            aggregator.include_signer(i, participants_public_comshares[(i-1) as usize].commitments[0], (&participants_secret_keys[(i-1) as usize]).into());
        }

        let signers = aggregator.get_signers().clone();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        for i in 1..t+1 {
            let pi_partial_signature = participants_secret_keys[(i-1) as usize].sign(&message_hash, &group_key, &mut participants_secret_comshares[(i-1) as usize], 0, &signers).unwrap();
            aggregator.include_partial_signature(pi_partial_signature);
        }

        let aggregator = aggregator.finalize().unwrap();

        let bench_name = name.to_string() + "Signature aggregation";
        c.bench_function(&bench_name, move |b| {
            b.iter(|| aggregator.aggregate());
        });
    }

    fn verify_t_out_of_n(name: &str, n: u32, t: u32, c: &mut Criterion) {
        let params = Parameters { n, t };

        let mut participants = Vec::<Participant>::with_capacity(n as usize);
        let mut coefficients = Vec::<Coefficients>::with_capacity(n as usize);
        let mut dh_secret_keys = Vec::<DHPrivateKey>::with_capacity(n as usize);

        for i in 1..n+1 {
            let (p, c, dh_sk) = Participant::new(&params, i, "Φ");
            participants.push(p);
            coefficients.push(c);
            dh_secret_keys.push(dh_sk);
        }

        let mut participants_encrypted_secret_shares: Vec<Vec::<EncryptedSecretShare>> = 
                (0..n).map(|_| Vec::with_capacity((n - 1) as usize)).collect();
        
        let mut participants_states_1 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(n as usize);
        let mut participants_states_2 = Vec::<DistributedKeyGeneration::<_>>::with_capacity(n as usize);

        for i in 1..n+1 {
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

        let mut p1_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((n - 1) as usize);
        for j in 2..n+1 {
            p1_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][0].clone());
        }
        participants_states_2.push(participants_states_1[0].clone().to_round_two(p1_my_encrypted_secret_shares).unwrap());

        for i in 2..n+1 {
            let mut pi_my_encrypted_secret_shares = Vec::<EncryptedSecretShare>::with_capacity((n - 1) as usize);
            let mut increment = -1i32;
            for j in 1..i {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][((i-j) as i32 + increment) as usize].clone());
                increment += 1;
            }
            for j in (i+1)..n+1 {
                pi_my_encrypted_secret_shares.push(participants_encrypted_secret_shares[(j-1) as usize][(i-1) as usize].clone());
            }

            participants_states_2.push(participants_states_1[(i-1) as usize].clone().to_round_two(pi_my_encrypted_secret_shares).unwrap());
        }

        let mut participants_secret_keys = Vec::<IndividualSecretKey>::with_capacity(t as usize);
        let (group_key, p1_sk) = participants_states_2[0].clone().finish(participants[1].public_key().unwrap()).unwrap();
        participants_secret_keys.push(p1_sk);

        for i in 2..t+1 {
            let (_, pi_sk) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].public_key().unwrap()).unwrap();
            participants_secret_keys.push(pi_sk);
        }
        for i in (t+2)..n+1 {
            let (_, _) = participants_states_2[(i-1) as usize].clone().finish(participants[(i-1) as usize].public_key().unwrap()).unwrap();
        }

        let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
        let message = b"This is a test of the tsunami alert system. This is only a test.";

        let mut participants_public_comshares = Vec::<PublicCommitmentShareList>::with_capacity(n as usize);
        let mut participants_secret_comshares = Vec::<SecretCommitmentShareList>::with_capacity(n as usize);
        let (p1_public_comshares, p1_secret_comshares) = generate_commitment_share_lists(&mut OsRng, 1, 1);
        participants_public_comshares.push(p1_public_comshares);
        participants_secret_comshares.push(p1_secret_comshares);

        for i in 2..n+1 {
            let (pi_public_comshares, pi_secret_comshares) = generate_commitment_share_lists(&mut OsRng, i, 1);
            participants_public_comshares.push(pi_public_comshares);
            participants_secret_comshares.push(pi_secret_comshares);
        }

        let mut aggregator = SignatureAggregator::new(params, group_key, &context[..], &message[..]);

        for i in 1..t+1 {
            aggregator.include_signer(i, participants_public_comshares[(i-1) as usize].commitments[0], (&participants_secret_keys[(i-1) as usize]).into());
        }

        let signers = aggregator.get_signers().clone();
        let message_hash = compute_message_hash(&context[..], &message[..]);

        for i in 1..t+1 {
            let pi_partial_signature = participants_secret_keys[(i-1) as usize].sign(&message_hash, &group_key, &mut participants_secret_comshares[(i-1) as usize], 0, &signers).unwrap();
            aggregator.include_partial_signature(pi_partial_signature);
        }

        let aggregator = aggregator.finalize().unwrap();
        let threshold_signature = aggregator.aggregate().unwrap();

        let bench_name = name.to_string() + "Signature verification";
        c.bench_function(&bench_name, move |b| {
            b.iter(|| threshold_signature.verify(&group_key, &message_hash));
        });
    }

    fn sig_bench_with_t_out_of_n(n: u32, t: u32, c: &mut Criterion) {
        let name = t.to_string() + "-out-of-" + &n.to_string() + ": ";
        partial_sign_t_out_of_n(&name, n, t, c);
        signature_aggregation_t_out_of_n(&name, n, t, c);
        verify_t_out_of_n(&name, n, t, c);
    }

    fn sig_bench(c: &mut Criterion) {
        sig_bench_with_t_out_of_n(100, 34, c);
        sig_bench_with_t_out_of_n(100, 67, c);
        sig_bench_with_t_out_of_n(200, 67, c);
        sig_bench_with_t_out_of_n(200, 134, c);
        sig_bench_with_t_out_of_n(300, 101, c);
        sig_bench_with_t_out_of_n(300, 201, c);
        sig_bench_with_t_out_of_n(500, 167, c);
        sig_bench_with_t_out_of_n(500, 334, c);
    }

    criterion_group! {
        name = sign_benches;
        config = Criterion::default().sample_size(10);
        targets = sig_bench,
    }
}

criterion_main!(
    dkg_benches::dkg_benches,
    sign_benches::sign_benches,
);
