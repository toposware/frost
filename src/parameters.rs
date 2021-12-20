// -*- mode: rust; -*-
//
// This file is part of dalek-frost.
// Copyright (c) 2020 isis lovecruft
// Copyright (c) 2021 Toposware Inc.
// See LICENSE for licensing information.
//
// Authors:
// - isis agora lovecruft <isis@patternsinthevoid.net>
// - Toposware developers <dev@toposware.com>

//! Configurable parameters for an instance of a FROST signing protocol.

use core::convert::TryInto;
use crate::keygen::Error;

/// The configuration parameters for conducting the process of creating a
/// threshold signature.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct Parameters {
    /// The number of participants in the scheme.
    pub n: u32,
    /// The threshold required for a successful signature.
    pub t: u32,
}

impl Parameters {
    /// Serialise these parameters as an array of bytes
    pub fn to_bytes(&self) -> [u8; 8] {
        let mut res = [0u8; 8];
        res[0..4].copy_from_slice(&self.n.to_le_bytes());
        res[4..8].copy_from_slice(&self.t.to_le_bytes());

        res
    }

    /// Deserialise this slice of bytes to `Parameters`
    pub fn from_bytes(bytes: &[u8]) -> Result<Parameters, Error> {
        let n = u32::from_le_bytes(
            bytes[0..4]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );
        let t = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .map_err(|_| Error::SerialisationError)?,
        );

        Ok(Parameters { n, t })
    }
}
