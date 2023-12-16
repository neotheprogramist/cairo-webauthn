pub mod account {
    use cainome::rs::abigen;

    abigen!(
        CartridgeAccount,
        "./abi/account.abi.json",
        type_aliases {
            openzeppelin::introspection::src5::SRC5::Event as SRC5Event;
            webauthn_auth::component::webauthn_component::Event as WebauthnEvent;
        }
    );
}

pub mod erc20 {
    use cainome::rs::abigen;

    abigen!(Erc20Contract, "./abi/erc20.abi.json");
}
