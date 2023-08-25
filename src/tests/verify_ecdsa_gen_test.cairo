// This file is script-generated.
// Don't modify it manually!
// See test_gen_scripts/verify_ecdsa_test.py for details
use core::traits::Into;
use core::option::OptionTrait;
use webauthn::ecdsa::{verify_ecdsa, verify_hashed_ecdsa, VerifyEcdsaError};
use starknet::secp256r1::Secp256r1Impl;
use starknet::secp256r1::Secp256r1Point;
use starknet::SyscallResultTrait;
use array::ArrayTrait;

#[test]
#[available_gas(200000000000)]
fn test_verify_ecdsa_short() {
    let pub_key = Secp256r1Impl::secp256_ec_new_syscall(
        66386131120069690357911524678077574461905205816429510392028773410168806435313,
        779525484024799793794293982898472885908190628827957055290684063043868439467
    )
        .unwrap_syscall()
        .unwrap();
    let r = 65447034036133507078952513143584276375798837793310008744831843317880448126314;
    let s = 72001488242829508755907929457472572345575776116175616103083199914174221979450;
    let msg = 49;

    match verify_hashed_ecdsa(pub_key, msg, r, s) {
        Result::Ok => (),
        Result::Err(m) => assert(false, m.into())
    }
}

#[test]
#[available_gas(200000000000)]
fn test_verify_ecdsa() {
    let pub_key = Secp256r1Impl::secp256_ec_new_syscall(
        77290834091360148577668494418309966013887926098336316994646351224509952644071,
        38083521470447754918580647852082180548468644517057300652114041174779866305408
    )
        .unwrap_syscall()
        .unwrap();
    let r = 12627125887502581483571162518569919098594844571076773113139068133824507751068;
    let s = 77201170888445069281390268653145314475094312146943065214348276605646557801580;
    let msg = 22405534230753928650781647905;

    match verify_hashed_ecdsa(pub_key, msg, r, s) {
        Result::Ok => (),
        Result::Err(m) => assert(false, m.into())
    }
}

#[test]
#[available_gas(200000000000)]
fn test_verify_ecdsa_long() {
    let pub_key = Secp256r1Impl::secp256_ec_new_syscall(
        44970771811546000998112153143378163139424152217507831884420635111234997060958,
        11883244840888449234576180103783891542802853452180439956309499948868552440813
    )
        .unwrap_syscall()
        .unwrap();
    let r = 81655932962612595060266721001830451552822383679690837825684125624882549641375;
    let s = 23465020737378692998484181401506511047525240847683181990334625621839346896237;
    let msg = 149135777980097582634002128993283245052269503470703527156581804847063441697;

    match verify_hashed_ecdsa(pub_key, msg, r, s) {
        Result::Ok => (),
        Result::Err(m) => assert(false, m.into())
    }
}

#[test]
#[available_gas(200000000000)]
fn test_ecdsa_wrong_arguments() {
    let pub_key = Secp256r1Impl::secp256_ec_new_syscall(
        31329206856343862026782871485154799088452767685421183721521170060282515362501,
        28246519623923867638754441723342230886156386866994507260572878326290946062507
    )
        .unwrap_syscall()
        .unwrap();
    let r = 0;
    let s = 0;
    let msg = 6214289900658384436962189733492;

    match verify_hashed_ecdsa(pub_key, msg, r, s) {
        Result::Ok => assert(false, 'Should Error!'),
        Result::Err(m) => match m {
            VerifyEcdsaError::WrongArgument => (),
            VerifyEcdsaError::InvalidSignature => assert(false, 'Wrong Error!'),
            VerifyEcdsaError::SyscallError => assert(false, 'Wrong Error!'),
        }
    }
}

#[test]
#[available_gas(200000000000)]
fn test_ecdsa_invalid_signature() {
    let pub_key = Secp256r1Impl::secp256_ec_new_syscall(
        28507077483881028284251219912298363224505246580809052262011440960406397847138,
        80142473863437057569876854192067166685096897358504849709239415825444342502167
    )
        .unwrap_syscall()
        .unwrap();
    let r = 105138106919176191795584747345860621523275889136761585799874882091500516263633;
    let s = 68661403054006506548193902682694641343868335971490177361094492250877843613914;
    let msg = 111110000011111;

    match verify_hashed_ecdsa(pub_key, msg, r, s) {
        Result::Ok => assert(false, 'Should Error!'),
        Result::Err(m) => match m {
            VerifyEcdsaError::WrongArgument => assert(false, 'Wrong Error!'),
            VerifyEcdsaError::InvalidSignature => (),
            VerifyEcdsaError::SyscallError => assert(false, 'Wrong Error!'),
        }
    }
}

#[test]
#[available_gas(200000000000)]
fn test_verify_ecdsa_with_hash_0() {
    let pub_key = Secp256r1Impl::secp256_ec_new_syscall(
        92938196251260031890055534447254687342929450811363684119374132655353262090465,
        69527133195060157921485811987447044767277150700847993534556442681805900282250
    )
        .unwrap_syscall()
        .unwrap();
    let r = 62832584624277282802890482358208429783245866820444593816103488255176435862973;
    let s = 13824750313558477166274059382083691172904311747156361810484510362684549489004;
    let mut msg: Array<u8> = ArrayTrait::new();
    msg.append(0x31);

    match verify_ecdsa(pub_key, msg, r, s) {
        Result::Ok => (),
        Result::Err(m) => assert(false, m.into())
    }
}

#[test]
#[available_gas(200000000000)]
fn test_verify_ecdsa_with_hash_1() {
    let pub_key = Secp256r1Impl::secp256_ec_new_syscall(
        28360716965244261303404519479152511413699429122919045796492467619298393481337,
        26924347318290976670103942351740144612087642117917547097453877322338718178798
    )
        .unwrap_syscall()
        .unwrap();
    let r = 86063993846196915750704948192300263647074118651479797106899022516817295123825;
    let s = 37049433581543347796379583320749424954091432263751825316655453299244145635487;
    let mut msg: Array<u8> = ArrayTrait::new();
    msg.append(0x48);
    msg.append(0x65);
    msg.append(0x6c);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x20);
    msg.append(0x57);
    msg.append(0x6f);
    msg.append(0x72);
    msg.append(0x6c);
    msg.append(0x64);
    msg.append(0x21);

    match verify_ecdsa(pub_key, msg, r, s) {
        Result::Ok => (),
        Result::Err(m) => assert(false, m.into())
    }
}

#[test]
#[available_gas(200000000000)]
fn test_verify_ecdsa_with_hash_2() {
    let pub_key = Secp256r1Impl::secp256_ec_new_syscall(
        67796208937113290812511929224871687366888965305716706443309283372699764168405,
        67252064213775881003785422794010929361189129540536529076905515901756111416496
    )
        .unwrap_syscall()
        .unwrap();
    let r = 37059660262842812835897689026713882275995233507907446647963049595922539789950;
    let s = 99809631212898864887838759117651976124013103727138621069823449560891710249718;
    let mut msg: Array<u8> = ArrayTrait::new();
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x4c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x61);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6d);
    msg.append(0x65);
    msg.append(0x73);
    msg.append(0x73);
    msg.append(0x61);
    msg.append(0x67);
    msg.append(0x65);
    msg.append(0x2c);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);
    msg.append(0x20);
    msg.append(0x71);
    msg.append(0x75);
    msg.append(0x69);
    msg.append(0x74);
    msg.append(0x65);
    msg.append(0x20);
    msg.append(0x6c);
    msg.append(0x6f);
    msg.append(0x6e);
    msg.append(0x67);

    match verify_ecdsa(pub_key, msg, r, s) {
        Result::Ok => (),
        Result::Err(m) => assert(false, m.into())
    }
}
