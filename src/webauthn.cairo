use core::clone::Clone;
use core::serde::Serde;
use core::starknet::secp256_trait::Secp256PointTrait;
use core::traits::Destruct;
use core::traits::Into;
use array::ArrayTrait;
use integer::upcast;
use debug::PrintTrait;
use option::OptionTrait;
use result::ResultTrait;
use starknet::secp256r1;
use starknet::secp256r1::Secp256r1Point;
use starknet::secp256r1::Secp256r1Impl;
use starknet::secp256r1::Secp256r1PointImpl;
use starknet::secp256_trait::recover_public_key;
use starknet::secp256_trait::Signature;

use alexandria_math::sha256::sha256;
use alexandria_encoding::base64::Base64UrlEncoder;
use alexandria_math::karatsuba;
use alexandria_math::BitShift;
use webauthn::ecdsa::verify_ecdsa;

fn sha256_u256(mut data: Array<u8>) -> u256 {
    let mut msg_hash_u256 = 0_u256;
    let msg_hash = sha256(data);
    msg_hash_u256 = msg_hash_u256 | BitShift::shl((*msg_hash[0]).into(), 0 * 8);
    msg_hash_u256 = msg_hash_u256 | BitShift::shl((*msg_hash[1]).into(), 1 * 8);
    msg_hash_u256 = msg_hash_u256 | BitShift::shl((*msg_hash[2]).into(), 2 * 8);
    msg_hash_u256 = msg_hash_u256 | BitShift::shl((*msg_hash[3]).into(), 3 * 8);
    msg_hash_u256 = msg_hash_u256 | BitShift::shl((*msg_hash[4]).into(), 4 * 8);
    msg_hash_u256 = msg_hash_u256 | BitShift::shl((*msg_hash[5]).into(), 5 * 8);
    msg_hash_u256 = msg_hash_u256 | BitShift::shl((*msg_hash[6]).into(), 6 * 8);
    msg_hash_u256 = msg_hash_u256 | BitShift::shl((*msg_hash[7]).into(), 7 * 8);
    msg_hash_u256
}

// let msgh_0: u128 = (*(msg_hash[0])).into();
//     let msgh_1: u128 = (*(msg_hash[1])).into();
//     let msgh_2: u128 = (*(msg_hash[2])).into();
//     let msgh_3: u128 = (*(msg_hash[3])).into();
//     let msgh_4: u128 = (*(msg_hash[4])).into();
//     let msgh_5: u128 = (*(msg_hash[5])).into();
//     let msgh_6: u128 = (*(msg_hash[6])).into();
//     let msgh_7: u128 = (*(msg_hash[7])).into();


//     let h02 = msgh_5 & 4194303;
//     let d0 = msgh_7 + fpow(2_u128, 32) * msgh_6 + fpow(2_u128, 64) * h02.into();

//     let h10 = msgh_5 / 4194304;
//     let r10 = msgh_5 % 4194304;
//     let h13 = msgh_2 & 4095;
//     let d1 = h10 + msgh_4 * fpow(2_u128, 10) + msgh_3 * fpow(2_u128, 42) + h13 * fpow(2_u128, 74);

//     let h20 = msgh_2 / 4096;
//     let r20 = msgh_2 % 4096;
//     let d2 = h20 + msgh_1 * fpow(2_u128, 20) + msgh_0 * fpow(2_u128, 52);

fn verify(
    pub: Secp256r1Point, // public key as point on elliptic curve
    r: u256, // 'r' part from ecdsa
    s: u256, // 's' part from ecdsa
    type_offset: usize, // offset to 'type' field in json
    challenge_offset: usize, // offset to 'challenge' field in json
    origin_offset: usize, // offset to 'origin' field in json
    client_data_json: Array<u8>, // json with client_data as 1-byte array 
    challenge: Array<u8>, // origin as 1-byte array
    origin: Array<u8>, // challenge as 1-byte array
    authenticator_data: Array<u8> // authenticator data as 1-byte array
) -> Result<(), felt252> {
    let msg = get_msg_and_validate(
        type_offset,
        challenge_offset,
        origin_offset,
        client_data_json,
        challenge,
        origin,
        authenticator_data
    );

    let msg_hash = sha256(msg.clone());

    let msg_hash_u256 = sha256_u256(msg);
    
    let verify_result = verify_ecdsa(pub, msg_hash_u256, r, s);
    match verify_result {
        Result::Ok => (),
        Result::Err(m) => {
            return Result::Err(m.into());
        }
    };
    
    // let signature = Signature { r, s, y_parity: false };
    // let result: Option<Secp256r1Point> = recover_public_key(msg_hash_u256, signature);
    // match result {
    //     Option::Some(res) => {
    //         let (x0, x1) = match res.get_coordinates() {
    //             Result::Ok(x) => x,
    //             Result::Err(_) => {
    //                 return Result::Err('bad signature');
    //             },
    //         };
    //         let (y0, y1) = match pub.get_coordinates() {
    //             Result::Ok(x) => x,
    //             Result::Err(_) => {
    //                 return Result::Err('bad signature');
    //             },
    //         };
    //         if x0 != y0 {
    //             return Result::Err('bad signature');
    //         }
    //         if x1 != y1 {
    //             return Result::Err('bad signature');
    //         }
    //     },
    //     Option::None(()) => {
    //         return Result::Err('bad signature');
    //     },
    // }

    Result::Ok(())
}


// Verifies structure as in https://www.w3.org/TR/webauthn/#sctn-verifying-assertion
// Generates binary concatenation of authenticator_data and hash of client_data for signature validation
// Implementation and comments based on https://github.com/cartridge-gg/cairo-webauthn/blob/main/src/webauthn.cairo
fn get_msg_and_validate(
    type_offset: usize, // offset to 'type' field in json
    challenge_offset: usize, // offset to 'challenge' field in json
    origin_offset: usize, // offset to 'origin' field in json
    client_data_json: Array<u8>, // json with client_data as 1-byte array 
    challenge: Array<u8>, // challenge as 1-byte array
    origin: Array<u8>, // origin as 1-byte array
    authenticator_data: Array<u8> // authenticator data as 1-byte array
) -> Array<u8> {
    // 11. Verify that the value of C.type is the string webauthn.get
    // Skipping for now

    // 12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.
    verify_challenge(@client_data_json, challenge_offset, challenge);

    // 13. Verify that the value of C.origin matches the Relying Party's origin.
    // Skipping for now.

    // 15. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.
    // Skipping for now. This protects against authenticator cloning which is generally not
    // a concern of blockchain wallets today.
    // Authenticator Data layout looks like: [ RP ID hash - 32 bytes ] [ Flags - 1 byte ] [ Counter - 4 byte ] [ ... ]
    // See: https://w3c.github.io/webauthn/#sctn-authenticator-data

    // 16. Verify that the User Present (0) and User Verified (2) bits of the flags in authData is set.
    verify_auth_flags(@authenticator_data);

    // 17. Skipping extensions

    // 18. Compute hash of client_data
    let client_data_hash = sha256(client_data_json);

    // Compute message ready for verification.
    let mut msg = authenticator_data;
    extend(ref msg, @client_data_hash);
    msg
}

fn verify_challenge(client_data_json: @Array<u8>, challenge_offset: usize, challenge: Array<u8>) {
    let challenge : Array<u8> = Base64UrlEncoder::encode(challenge);
    let mut i: usize = 0;
    let challenge_len: usize = challenge.len();
    loop {
        // Base64UrlEncoder at the moment pads with '=' => remove -1 later {assumes len == 43} or 
        // additionally break on '=' sign
        if i == challenge_len - 1 {
            break ();
        }
        assert(
            *client_data_json.at(challenge_offset + i) == *challenge.at(i), 'invalid challenge'
        );
        i += 1_usize;
    }
}

fn verify_auth_flags(authenticator_data: @Array<u8>) {
    let flags: u128 = upcast(*authenticator_data.at(32_usize));
    let mask: u128 = upcast(1_u8 + 4_u8);
    assert((flags & mask) == mask, 'invalid flags');
}

fn extend(ref arr: Array<u8>, src: @Array<u8>) {
    let mut i: usize = 0;
    let end: usize = src.len();
    loop {
        if i == end {
            break ();
        }
        arr.append(*src.at(i));
        i += 1_usize;
    }
}

//Fixed - doesn't cause overflow, for there is a bug in alexandria
fn fpow(x: u128, n: u128) -> u128 {
    if n == 0 {
        1
    } else if n == 1{
        x
    } else if (n & 1) == 1 {
        x * fpow(x * x, n / 2)
    } else {
        fpow(x * x, n / 2)
    }
}
