mod account;
mod sequence;
mod session;
mod signature;

pub use account::SessionAccount;
pub use sequence::CallSequence;
pub use session::Session;
pub use signature::SessionSignature;
use starknet::{core::types::FieldElement, macros::felt};

pub const SIGNATURE_TYPE: FieldElement = felt!("0x53657373696f6e20546f6b656e207631"); // 'Session Token v1'

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use starknet::{
        accounts::{Account, Call, ConnectedAccount},
        macros::selector,
        signers::{LocalWallet, SigningKey},
    };
    use tokio::time::sleep;

    use crate::tests::{
        deployment_test::create_account,
        runners::{KatanaRunner, TestnetRunner},
    };

    use super::*;

    #[tokio::test]
    async fn test_session_valid() {
        let runner = KatanaRunner::load();
        let master = create_account(&runner.prefunded_single_owner_account().await).await;

        let session_key = LocalWallet::from(SigningKey::from_random());

        let session = Session::default();
        let (chain_id, address) = (master.chain_id(), master.address());
        let provider = *master.provider();
        let account = SessionAccount::new(provider, session_key, session, address, chain_id);

        let calls = vec![Call {
            to: address,
            selector: selector!("revoke_session"),
            calldata: vec![FieldElement::from(0x2137u32)],
        }];

        sleep(Duration::from_secs(10)).await;
        account.execute(calls.clone()).send().await.unwrap();
    }

    #[tokio::test]
    async fn test_session_revoked() {
        let runner = KatanaRunner::load();
        let master = create_account(&runner.prefunded_single_owner_account().await).await;

        let session_key = LocalWallet::from(SigningKey::from_random());

        let session = Session::default();
        let (chain_id, address) = (master.chain_id(), master.address());
        let provider = *master.provider();
        let account = SessionAccount::new(provider, session_key, session, address, chain_id);

        let calls = vec![Call {
            to: address,
            selector: selector!("revoke_session"),
            calldata: vec![FieldElement::from(0x2137u32)],
        }];

        account.execute(calls.clone()).send().await.unwrap();
        sleep(Duration::from_millis(100)).await;
        let result = account.execute(calls.clone()).send().await;

        assert!(result.is_err());
    }
}
