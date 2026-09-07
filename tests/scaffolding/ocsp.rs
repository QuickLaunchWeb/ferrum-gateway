//! A minimal, positive-only stapled-OCSP fixture for integration tests
//! (issue #4505).
//!
//! `tests/unit/tls/ocsp_validation_tests.rs` owns the exhaustive DER builder
//! that expresses malformed and mis-bound encodings; that machinery lives in
//! the unit binary and cannot be shared across test targets. What integration
//! tests need is narrower and is all that is built here: a real CA, a real
//! leaf beneath it, and a genuine issuer-signed `BasicOCSPResponse` whose
//! validity window the caller chooses, so a staple can be made to reach its
//! `nextUpdate` inside a test.

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

const OID_SHA1: &[u8] = &[0x2b, 0x0e, 0x03, 0x02, 0x1a];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_OCSP_BASIC: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

const LEAF_SERIAL: u64 = 0x4505;

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(bytes.len() - 1);
        let significant = &bytes[first..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn explicit(number: u8, content: &[u8]) -> Vec<u8> {
    tlv(0xa0 | number, content)
}

fn octet_string(content: &[u8]) -> Vec<u8> {
    tlv(0x04, content)
}

fn oid(content: &[u8]) -> Vec<u8> {
    tlv(0x06, content)
}

fn algorithm_identifier(oid_bytes: &[u8]) -> Vec<u8> {
    sequence(&[oid(oid_bytes)])
}

fn bit_string(content: &[u8]) -> Vec<u8> {
    let mut body = vec![0_u8];
    body.extend_from_slice(content);
    tlv(0x03, &body)
}

fn generalized_time(unix: i64) -> Vec<u8> {
    let datetime =
        time::OffsetDateTime::from_unix_timestamp(unix).expect("representable GeneralizedTime");
    let rendered = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    );
    tlv(0x18, rendered.as_bytes())
}

fn serial_bytes(serial: u64) -> Vec<u8> {
    let mut bytes = serial.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    bytes
}

fn sha1(data: &[u8]) -> Vec<u8> {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .to_vec()
}

/// A CA, a leaf it issued, and the CA key retained so the same key can sign
/// `tbsResponseData`.
pub struct StapledPki {
    issuer_pkcs8: Vec<u8>,
    issuer_der: Vec<u8>,
    /// Leaf + issuer, in the order rustls serves them.
    pub chain_pem: String,
    pub leaf_key_pem: String,
}

impl StapledPki {
    /// Build a fresh two-certificate PKI with P-256 keys throughout.
    pub fn generate() -> Self {
        let issuer_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("issuer key");
        let issuer_pkcs8 = issuer_pair.serialize_der();
        let mut issuer_params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("issuer params");
        issuer_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        issuer_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Ferrum OCSP Staple Test CA");
        issuer_params
            .key_usages
            .push(rcgen::KeyUsagePurpose::KeyCertSign);
        let issuer_cert = issuer_params
            .self_signed(&issuer_pair)
            .expect("self-sign CA");
        let issuer_der = issuer_cert.der().to_vec();
        let issuer_pem = issuer_cert.pem();
        let issuer = rcgen::Issuer::new(issuer_params, issuer_pair);

        let leaf_pair =
            rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
        let mut leaf_params =
            rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
        leaf_params.serial_number = Some(rcgen::SerialNumber::from(LEAF_SERIAL));
        leaf_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "localhost");
        leaf_params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let leaf_cert = leaf_params
            .signed_by(&leaf_pair, &issuer)
            .expect("issue leaf");

        Self {
            issuer_pkcs8,
            issuer_der,
            chain_pem: format!("{}{}", leaf_cert.pem(), issuer_pem),
            leaf_key_pem: leaf_pair.serialize_pem(),
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let rng = SystemRandom::new();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.issuer_pkcs8, &rng)
                .expect("issuer signing key");
        assert!(!key.public_key().as_ref().is_empty());
        key.sign(&rng, message).expect("sign").as_ref().to_vec()
    }

    /// A `good` response for this PKI's leaf, valid over
    /// `[this_update, next_update)` (both Unix seconds), signed by the issuer
    /// itself (no delegated responder).
    pub fn ocsp_response(&self, this_update: i64, next_update: i64) -> Vec<u8> {
        let (_, issuer) = X509Certificate::from_der(&self.issuer_der).expect("parse issuer");
        let name_hash = sha1(issuer.subject().as_raw());
        let key_hash = sha1(issuer.public_key().subject_public_key.data.as_ref());

        let cert_id = sequence(&[
            algorithm_identifier(OID_SHA1),
            octet_string(&name_hash),
            octet_string(&key_hash),
            tlv(0x02, &serial_bytes(LEAF_SERIAL)),
        ]);
        let single = sequence(&[
            cert_id,
            // good [0] IMPLICIT NULL
            tlv(0x80, &[]),
            generalized_time(this_update),
            explicit(0, &generalized_time(next_update)),
        ]);

        let response_data = sequence(&[
            explicit(1, issuer.subject().as_raw()),
            generalized_time(this_update),
            sequence(&[single]),
        ]);
        let signature = self.sign(&response_data);
        let basic = sequence(&[
            response_data,
            algorithm_identifier(OID_ECDSA_SHA256),
            bit_string(&signature),
        ]);

        sequence(&[
            tlv(0x0a, &[0]),
            explicit(0, &sequence(&[oid(OID_OCSP_BASIC), octet_string(&basic)])),
        ])
    }
}
