// Copyright 2016 Peter Reid. See the COPYRIGHT file at the top-level
// directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! In cryptography, keystreams are sequences of bytes that can be
//! XORed with a plaintext to create a ciphertext or XORed with a
//! ciphertext to recover the plaintext. A good keystream is
//! nearly impossible to distinguish from random stream of bytes,
//! which makes the ciphertext appear similarly random.
//!
//! This crate contains traits that that encapsulate the behavior
//! of keystreams, which allows cryptographic operations that
//! depend on keystreams be generic over which particular keystream
//! they use.

#![no_std]

/// An error when generating a keystream
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    EndReached
}

/// Types that encapsulate a stream of bytes that to be combined with a cryptographic
/// plaintext or ciphertext
pub trait KeyStream {
    /// XORs keystream bytes with `dest`.
    ///
    /// If the end of the keystream is reached, this returns an error and the contents of
    /// dest are undefined.
    fn xor_read(&mut self, dest: &mut [u8]) -> Result<(), Error>;
}

/// KeyStreams that allow efficiently moving to positions in the stream
pub trait SeekableKeyStream: KeyStream {
    /// Seeks to a position, with byte resolution, in the keystream.
    ///
    /// Returns an error if the seek would pass the end of the keystream.
    fn seek_to(&mut self, byte_offset: u64) -> Result<(), Error>;
}
