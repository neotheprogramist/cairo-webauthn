use starknet::{core::types::FieldElement, macros::felt, signers::SigningKey};

#[derive(Clone)]
pub struct Session {
    r: FieldElement,
    s: FieldElement,
    session_key: FieldElement,
    session_expires: u64,
    root: FieldElement,
    proof_len: u32,
    proofs: Vec<FieldElement>,
    session_token: Vec<FieldElement>,
}

impl Session {
    pub fn sign(&mut self, signing: &SigningKey) {
        let hash = FieldElement::from(2137u32);
        let signature = signing.sign(&hash).unwrap();
        self.r = signature.r;
        self.s = signature.s;
        self.session_key = signing.verifying_key().scalar();
    }
}

impl Default for Session {
    fn default() -> Self {
        Self {
            r: felt!("0x42"),
            s: felt!("0x43"),
            session_key: felt!("0x69"),
            session_expires: u64::MAX,
            root: felt!("0x0"),
            proof_len: 1,
            proofs: vec![felt!("44")],
            session_token: vec![felt!("2137")],
        }
    }
}

impl Into<Vec<FieldElement>> for Session {
    fn into(self) -> Vec<FieldElement> {
        let mut result = Vec::new();
        result.push(self.r);
        result.push(self.s);
        result.push(self.session_key);
        result.push(self.session_expires.into());
        result.push(self.root);
        result.push(self.proof_len.into());
        result.push(self.proofs.len().into());
        result.extend(self.proofs);
        result.push(self.session_token.len().into());
        result.extend(self.session_token);
        result
    }
}