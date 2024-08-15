---
v: 3
title: "COSE Hash Envelope"
cat: std
docname: draft-ietf-cose-hash-envelope-latest
stream: IETF
number:
consensus: true
area: "Security"
keyword: Internet-Draft
venue:
  group: "CBOR Object Signing and Encryption"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"
  github: "cose-wg/draft-ietf-cose-hash-envelope"
  latest: "https://cose-wg.github.io/draft-ietf-cose-hash-envelope/draft-ietf-cose-hash-envelope.html"

author:

  - fullname: Orie Steele
    organization: Transmute
    email: orie@transmute.industries

  - fullname: Steve Lasker
    organization: DataTrails
    email: steve.lasker@datatrails.ai

  - ins: H. Birkholz
    name: Henk Birkholz
    org: Fraunhofer SIT
    abbrev: Fraunhofer SIT
    email: henk.birkholz@ietf.contact
    street: Rheinstrasse 75
    code: '64295'
    city: Darmstadt
    country: Germany

normative:
  RFC9052: RFC9052

informative:

--- abstract

This document defines new COSE header parameters for signaling a payload as an output of a hash function.
This mechanism enables faster validation as access to the original payload is not required for signature validation.
Additionally, hints of the detached payload's content format and availability are defined providing references to optional discovery mechanisms that can help to find original payload content.

--- middle

# Introduction

COSE defined detached payloads in Section 2 of {{-RFC9052}}, using `nil` as the payload.
In order to verify a signature over a detached payload, the verifier must have access to the payload content.
Storing a hash of the content allows for small signature envelopes, that are easy to transport and verify independently.

Additional hints in the protected header ensure cryptographic agility for the hashing & signing algorithms, and discoverability for the original content which could be prohibitively large to move over a network.

## Attached Payload

COSE_sign1 envelope with an attached payload, providing for signature validation.

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a4013822...3a616263',       / Protected                     /
      {}                            / Unprotected                   /
      h'317cedc7...c494e772',       / Payload                       /
      h'15280897...93ef39e5'        / Signature                     /
    ]
)
~~~~

## Detached Payload

COSE_sign1 envelope with a detached payload (`nil`), which is compact but the payload must be distributed out of band to validate the signature.

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a4013822...3a616263',       / Protected                     /
      {}                            / Unprotected                   /
      nil,                          / Detached Payload              /
      h'15280897...93ef39e5'        / Signature                     /
    ]
)
~~~~

## Hashed Payload

A hashed payload functions equivalently to an attached payload, with the benefits of being compact in size and providing the ability to validate the signature.

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a4013822...3a616263',       / Protected                     /
      {}                            / Unprotected                   /
      h'935b5a91...e18a588a',       / Payload                       /
      h'15280897...93ef39e5'        / Signature                     /
    ]
)
~~~~

# Header Parameters

To represent a hash of a payload, the following headers are defined:

TBD_1:
  : the hash algorithm used to generate the hash of the payload

TBD_2:
  : the content type of the payload the hash represents

TBD_3:
  : an identifier enabling a verifier to retrieve the full payload preimage.

## Signed Hash Envelopes Example

~~~ cddl
Hash_Envelope_Protected_Header = {
    ; Cryptographic algorithm to use
    ? &(alg: 1) => int,

    ; Type of the envelope
    ? &(typ: 16) => int / tstr

    ; Hash algorithm used to produce the payload from content
    ; -16 for SHA-256,
    ; See https://www.iana.org/assignments/cose/cose.xhtml
    &(payload_hash_alg: TBD_1) => int

    ; Content type of the preimage
    ; (content to be hashed) of the payload
    ; 50 for application/json,
    ; See https://datatracker.ietf.org/doc/html/rfc7252#section-12.3
    &(payload_preimage_content_type: TBD_2) => int

    ; Location the content of the hashed payload is stored
    ; For example:
    ; storage.example/244f...9c19
    ? &(payload_location: TBD_3) => tstr

    * int => any
}

Hash_Envelope_Unprotected_Header = {
    * int => any
}

Hash_Envelope_as_COSE_Sign1 = [
    protected : bstr .cbor Hash_Envelope_Protected_Header,
    unprotected : Hash_Envelope_Unprotected_Header,
    payload: bstr / nil,
    signature : bstr
]

Hash_Envelope = #6.18(Hash_Envelope_as_COSE_Sign1)
~~~

## Protected Header

16 (typ), TBD_1 (payload hash alg) and TBD_2 (content type of the preimage of the payload) MUST be present in the protected header and MUST NOT be present in the unprotected header.
TBD_3 (payload_location) MAY be added to the protected header and MUST NOT be presented in the unprotected header.

For example:

~~~~ cbor-diag
{
  / alg : ES384 / 1: -35,
  / kid / 4: h'75726e3a...32636573',
  / typ / 16: application/hashed+cose
  / payload_hash_alg sha-256 / TBD_1: 1
  / payload_preimage_content_type / TBD_2: application/jwk+json
  / payload_location / TBD_3 : storage.example/244f...9c19
}
~~~~

# Encrypted Hashes

Should we define this?

# Security Considerations

TODO Security

## Choice of Hash Function

It is RECOMMENDED to align the strength of the chosen hash function to the strength of the chosen signature algorithm.
For example, when signing with ECDSA using P-256 and SHA-256, use SHA-256 to hash the payload.

# IANA Considerations

## Requirements Notation

{::boilerplate bcp14-tagged}

## COSE Header Algorithm Parameters

- Name: payload hash algorithm
- Label: TBD_1
- Value type: int
- Value registry: https://www.iana.org/assignments/named-information/named-information.xhtml
- Description: Hash algorithm used to produce the payload.

## Named Information Hash Algorithm Registry

- Name: SHAKE256
- Label: TBD_2
- Value type: int
- Value registry: https://www.iana.org/assignments/named-information/named-information.xhtml
- Description: SHAKE256 a described in https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

- Name: ASCON128
- Label: TBD_3
- Value type: int
- Value registry: https://www.iana.org/assignments/named-information/named-information.xhtml
- Description: ASCON128 a described in https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/ascon-spec-round2.pdf

--- back

# Acknowledgments
{:numbered="false"}

The following individuals provided input into the final form of the document: Carsten Bormann, Henk Birkholz, Antoine Delignat-Lavaud, Cedric Fournet.
