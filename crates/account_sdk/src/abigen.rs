pub mod account {
    use cainome::rs::abigen;

    abigen!(
        CartridgeAccount,
        "./crates/cartridge_account/abi/account.abi.json",
        type_aliases {
            openzeppelin::account::AccountComponent::Event as AccountEvent;
            openzeppelin::introspection::src5::SRC5::Event as SRC5Event;
            webauthn_session::session_component::Event as SessionEvent;
            webauthn_auth::component::webauthn_component::Event as WebauthnEvent;
        }
    );
}

pub mod erc20 {
    use cainome::rs::abigen;

    abigen!(
        Erc20Contract,
        "./crates/cartridge_account/abi/erc20.abi.json",
        type_aliases {
            openzeppelin::token::erc20::ERC20Component::Event as ERC20Event;
            openzeppelin::access::ownable::OwnableComponent::Event as OwnableEvent;
        }
    );
}
