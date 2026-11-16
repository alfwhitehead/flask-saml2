"""
SHA-256 is the default signature algorithm. SHA-1 signatures are rejected
when verifying, unless a handler explicitly opts in with ``allow_sha1``.
"""
from pathlib import Path

import pytest
from lxml import etree
from signxml.exceptions import InvalidInput

from flask_saml2.idp import IdentityProvider, SPHandler
from flask_saml2.idp.parser import AuthnRequestParser
from flask_saml2.signing import (
    RsaSha1Signer, RsaSha256Signer, Sha1Digester, Sha256Digester,
    SignatureTemplate)
from flask_saml2.sp import IdPHandler, ServiceProvider
from flask_saml2.utils import certificate_from_file, private_key_from_file

KEY_DIR = Path(__file__).parent / 'keys' / 'sample'
CERTIFICATE = certificate_from_file(KEY_DIR / 'salesforce-certificate.pem')
PRIVATE_KEY = private_key_from_file(KEY_DIR / 'salesforce-private-key.pem')
REQUEST_ID = '_ABC123_some_assertion_id'


def make_signed_request(digester, signer) -> bytes:
    request_xml = etree.fromstring(
        '<samlp:AuthnRequest '
        'xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'ID="' + REQUEST_ID + '" '
        'IssueInstant="2011-10-05T18:49:49.068Z" '
        'Version="2.0">'
        '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        'https://sp.example.com'
        '</saml:Issuer>'
        '</samlp:AuthnRequest>'
    )
    subject = etree.tostring(request_xml, method='c14n', exclusive=True)
    signature = SignatureTemplate.sign(
        subject.decode('utf-8'), CERTIFICATE, digester, signer, REQUEST_ID)
    request_xml.insert(1, signature.xml)
    return etree.tostring(request_xml, method='c14n', exclusive=True)


def test_sha256_signature_is_accepted():
    request = make_signed_request(Sha256Digester(), RsaSha256Signer(PRIVATE_KEY))
    parser = AuthnRequestParser(request, certificate=CERTIFICATE)
    assert parser.issuer == 'https://sp.example.com'


def test_sha1_signature_is_rejected_by_default():
    request = make_signed_request(Sha1Digester(), RsaSha1Signer(PRIVATE_KEY))
    with pytest.raises(InvalidInput):
        AuthnRequestParser(request, certificate=CERTIFICATE)


def test_sha1_signature_is_accepted_when_allowed():
    request = make_signed_request(Sha1Digester(), RsaSha1Signer(PRIVATE_KEY))
    parser = AuthnRequestParser(request, certificate=CERTIFICATE, allow_sha1=True)
    assert parser.issuer == 'https://sp.example.com'


def test_handlers_reject_sha1_by_default():
    assert SPHandler.allow_sha1 is False
    assert IdPHandler.allow_sha1 is False


def test_idp_signs_with_sha256_by_default():
    assert IdentityProvider.idp_digester_class is Sha256Digester
    assert IdentityProvider.idp_signer_class is RsaSha256Signer


def test_sp_signs_with_sha256_by_default():
    sp = ServiceProvider()
    sp.get_sp_private_key = lambda: PRIVATE_KEY
    assert isinstance(sp.get_sp_digester(), Sha256Digester)
    assert isinstance(sp.get_sp_signer(), RsaSha256Signer)
