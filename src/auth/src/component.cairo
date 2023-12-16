use starknet::account::Call;

#[starknet::interface]
trait IWebauthn<TContractState> {
    fn verifyWebauthnSigner(
        self: @TContractState, 
        pub_x: u256,
        pub_y: u256, // public key as point on elliptic curve
        r: u256, // 'r' part from ecdsa
        s: u256, // 's' part from ecdsa
        type_offset: usize, // offset to 'type' field in json
        challenge_offset: usize, // offset to 'challenge' field in json
        origin_offset: usize, // offset to 'origin' field in json
        client_data_json: Array<u8>, // json with client_data as 1-byte array 
        challenge: Array<u8>, // challenge as 1-byte array
        origin: Array<u8>, //  array origin as 1-byte array
        authenticator_data: Array<u8>
    ) -> bool;
}

// Based on https://github.com/argentlabs/starknet-plugin-account/blob/3c14770c3f7734ef208536d91bbd76af56dc2043/contracts/plugins/SessionKey.cairo
#[starknet::component]
mod webauthn_component {
    use core::result::ResultTrait;
    use starknet::info::{TxInfo, get_tx_info, get_block_timestamp};
    use starknet::account::Call;
    use ecdsa::check_ecdsa_signature;
    use starknet::secp256r1::{Secp256r1Point, Secp256r1Impl};
    use webauthn_auth::webauthn::verify;

    struct WebauthnPubKey{
        x: u256,
        y: u256,
    }

    #[storage]
    struct Storage {
        public_key: Option<WebauthnPubKey>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
    }


    #[embeddable_as(Webauthn)]
    impl WebauthnImpl<
        TContractState, +HasComponent<TContractState>
    > of super::IWebauthn<ComponentState<TContractState>> {
        fn verifyWebauthnSigner(
            self: @ComponentState<TContractState>, 
            pub_x: u256,
            pub_y: u256, // public key as point on elliptic curve
            r: u256, // 'r' part from ecdsa
            s: u256, // 's' part from ecdsa
            type_offset: usize, // offset to 'type' field in json
            challenge_offset: usize, // offset to 'challenge' field in json
            origin_offset: usize, // offset to 'origin' field in json
            client_data_json: Array<u8>, // json with client_data as 1-byte array 
            challenge: Array<u8>, // challenge as 1-byte array
            origin: Array<u8>, //  array origin as 1-byte array
            authenticator_data: Array<u8>
        ) -> bool{
            let pub_key = match 
                Secp256r1Impl::secp256_ec_new_syscall(pub_x, pub_y){
                    Result::Ok(pub_key) => pub_key,
                    Result::Err(e) => { return false; }
                };
            let pub_key = match pub_key {
                    Option::Some(pub_key) => pub_key,
                    Option::None => { return false; }
                };
            verify(
                pub_key, 
                r, 
                s, 
                type_offset, 
                challenge_offset, 
                origin_offset, 
                client_data_json, 
                challenge, 
                origin, 
                authenticator_data
            ).is_ok()
        }
    }

    #[generate_trait]
    #[external(v0)]
    impl InternalImpl<
        TContractState, +HasComponent<TContractState>
    > of InternalTrait<TContractState>  {
        
    }
}