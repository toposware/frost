
# ICE-FROST

A fork of the Rust implementation of [FROST: Flexible Round-Optimised Schnorr Threshold signatures](https://eprint.iacr.org/2020/852) by Chelsea Komlo and Ian Goldberg, originally developed at https://github.com/isislovecruft/frost-dalek and adapted to support additional Identifiable Cheating Entity property and Static group keys. This new protocol is named [ICE-FROST](https://eprint.iacr.org/2021/1658).

## Usage

Please see the documentation for usage examples.

## Note on `no_std` usage

This crate can be made `no_std` compliant, by relying on the `alloc` crate instead.

## WARNING

This codedebase is under development and is at an academic proof-of-concept prototype level.
In particular, this implementation has not received careful code review yet, and hence is NOT ready for production use.

## License

This project is licensed under the BSD-3-Clause.
