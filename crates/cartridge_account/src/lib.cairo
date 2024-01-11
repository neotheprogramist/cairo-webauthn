// SPDX-License-Identifier: MIT

mod signature_type;

#[starknet::contract]
mod Account {
    use core::ecdsa::check_ecdsa_signature;
    use openzeppelin::account::AccountComponent;
    use openzeppelin::account::interface;
    use openzeppelin::introspection::src5::SRC5Component::InternalTrait as SRC5InternalTrait;
    use openzeppelin::introspection::src5::SRC5Component;

    use starknet::account::Call;
    use starknet::get_tx_info;

    use webauthn_auth::webauthn::verify;
    use webauthn_session::session_component;
    use webauthn_auth::component::webauthn_component;

    use cartridge_account::signature_type::{SignatureType, SignatureTypeImpl};

    component!(path: AccountComponent, storage: account, event: AccountEvent);
    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: session_component, storage: session, event: SessionEvent);
    component!(path: webauthn_component, storage: webauthn, event: WebauthnEvent);

    #[abi(embed_v0)]
    impl SessionImpl = session_component::Session<ContractState>;
    #[abi(embed_v0)]
    impl WebauthnImpl = webauthn_component::Webauthn<ContractState>;

    #[abi(embed_v0)]
    impl SRC6Impl = AccountComponent::SRC6Impl<ContractState>;
    #[abi(embed_v0)]
    impl PublicKeyImpl = AccountComponent::PublicKeyImpl<ContractState>;
    #[abi(embed_v0)]
    impl SRC5Impl = SRC5Component::SRC5Impl<ContractState>;
    impl AccountInternalImpl = AccountComponent::InternalImpl<ContractState>;


    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: AccountComponent::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        #[substorage(v0)]
        session: session_component::Storage,
        #[substorage(v0)]
        webauthn: webauthn_component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: AccountComponent::Event,
        #[flat]
        SRC5Event: SRC5Component::Event,
        SessionEvent: session_component::Event,
        WebauthnEvent: webauthn_component::Event,
    }

    mod Errors {
        const INVALID_CALLER: felt252 = 'Account: invalid caller';
        const INVALID_SIGNATURE: felt252 = 'Account: invalid signature';
        const INVALID_TX_VERSION: felt252 = 'Account: invalid tx version';
        const UNAUTHORIZED: felt252 = 'Account: unauthorized';
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.account.initializer(public_key);
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn initializer(ref self: ContractState, _public_key: felt252) {
            self.src5.register_interface(interface::ISRC6_ID);
            self._set_public_key(_public_key);
        }

        fn validate_transaction(self: @ContractState, mut calls: Array<Call>) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let mut signature = tx_info.signature;
            if signature.len() == 2_u32 {
                return self.validate_ecdsa_transaction();
            }
            let signature_type = match SignatureTypeImpl::new(*signature.at(0_u32)) {
                Option::Some(signature_type) => signature_type,
                Option::None(_) => { return Errors::INVALID_SIGNATURE; },
            };
            match signature_type {
                SignatureType::SessionTokenV1 => {
                    SessionImpl::validate_session_serialized(
                        self, self.get_public_key(), signature, calls.span()
                    )
                },
                SignatureType::WebauthnV1 => {
                    WebauthnImpl::verify_webauthn_signer_serialized(self, signature, tx_hash)
                }
            }
        }

        fn validate_ecdsa_transaction(self: @ContractState) -> felt252 {
            let tx_info = get_tx_info().unbox();
            let tx_hash = tx_info.transaction_hash;
            let mut signature = tx_info.signature;
            if self.is_valid_ecdsa_signature(tx_hash, signature) {
                starknet::VALIDATED
            } else {
                Errors::INVALID_SIGNATURE
            }
        }

        fn _set_public_key(ref self: ContractState, new_public_key: felt252) {
            self.account.Account_public_key.write(new_public_key);
            self.account.emit(AccountComponent::OwnerAdded { new_owner_guid: new_public_key });
        }

        fn is_valid_ecdsa_signature(
            self: @ContractState, hash: felt252, signature: Span<felt252>
        ) -> bool {
            if signature.len() == 2_u32 {
                check_ecdsa_signature(
                    hash,
                    self.account.Account_public_key.read(),
                    *signature.at(0_u32),
                    *signature.at(1_u32)
                )
            } else {
                false
            }
        }
    }
}
