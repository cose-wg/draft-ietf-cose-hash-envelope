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
  RFC9052: COSE
  RFC8610: CDDL
  I-D.draft-ietf-cbor-edn-literals: EDN

informative:
  BCP205:

--- abstract

This document defines new COSE header parameters for signaling a payload as an output of a hash function.
This mechanism enables faster validation as access to the original payload is not required for signature validation.
Additionally, hints of the detached payload's content format and availability are defined providing references to optional discovery mechanisms that can help to find original payload content.

--- middle

# Introduction

COSE defined detached payloads in Section 2 of {{-COSE}}, using `nil` as the payload.
In order to verify a signature over a detached payload, the verifier must have access to the payload content.
Storing a hash of the content allows for small signature envelopes, that are easy to transport and verify independently.

Additional hints in the protected header ensure cryptographic agility for the hashing & signing algorithms, and discoverability for the original content which could be prohibitively large to move over a network.

When producing COSE_sign1 with remote signing services, such as a signing api exposed over HTTPS and backed by an HSM, the "ToBeSigned" bytes as described in {{Section 4.4 of RFC9052}} need to be transmitted to the HSM in order to be signed.

Some signature algorithms such as ES256 or ES384 allow the "ToBeSigned" to be hashed on the client and sent to the server along with metadata in order to produce a signature.

Other signature algorithms such as EdDSA with Ed25519, or ML-DSA do not expose such a capability.

By producing the "ToBeSigned" on the client, and ensuring that the payload is always a hashed value, the total size of the message to be sent to the servce for signing is constrained.

It is still possible for the protected header to be large, but the payload will always be of a fixed size, associated with the hash function chosen.

# Terminology

{::boilerplate bcp14-tagged}

The terms COSE, CDDL, and EDN are defined in {{-COSE}}, {{-CDDL}}, {{-EDN}} respectively.

To represent a hash of a payload, the following headers are defined:

TBD_1:
  : the hash algorithm used to produce the payload.

TBD_2:
  : the content type of the bytes that were hashed to produce the payload.

TBD_3:
  : an identifier enabling a verifier to retrieve the bytes which were hashed to produce the payload.

# Hash Envelope CDDL

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

    * int / tstr => any
}

Hash_Envelope_Unprotected_Header = {
    * int / tstr => any
}

Hash_Envelope_as_COSE_Sign1 = [
    protected : bstr .cbor Hash_Envelope_Protected_Header,
    unprotected : Hash_Envelope_Unprotected_Header,
    payload: bstr / nil,
    signature : bstr
]

Hash_Envelope = #6.18(Hash_Envelope_as_COSE_Sign1)
~~~

Label `16` (typ) MAY be used to assign a content format or media type to the entire hash envelope.
Label `TBD_1` (payload hash alg) MUST be present in the protected header and MUST NOT be present in the unprotected header.
Label `TBD_2` (content type of the preimage of the payload) MAY be present in the protected header or unprotected header.
Label `TBD_3` (payload_location) MAY be added to the protected header and MUST NOT be presented in the unprotected header.
Label `3` (content_type) MUST NOT be present in the protected or unprotected headers.
Label `3` is easily confused with label `TBD_2` payload_preimage_content_type.
The difference between content_type (3) and payload_preimage_content_type (TBD2) is that content_type is used to identify the content format associated with payload, whereas payload_preimage_content_type is used to identify the content format of the bytes which are hashed to produce the payload.

# Envelope EDN

A hashed payload functions equivalently to an attached payload, with the benefits of being compact in size and providing the ability to validate the signature.

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      <<{
        / alg : ES384 / 1: -35,
        / kid / 4: h'75726e3a...32636573',
        / typ / 16: "application/example+cose"
        / payload_hash_alg /
        TBD_1: -16 / sha-256 /
        / payload_preimage_content_type /
        TBD_2: "application/example+json"
        / payload_location /
        TBD_3 : "https://storage.example/a24f9c19"
      }>>
      {}                            / Unprotected                   /
      h'935b5a91...e18a588a',       / Payload                       /
      h'15280897...93ef39e5'        / Signature                     /
    ]
)
~~~~

In this example, the sha256 hash algorithm (-16) is used to hash the payload, which is of content type "application/example+json".
The full payload is located at "https://storage.example/244f...9c19".
The COSE_sign1 is of type "application/example+cose".
The sha256 hash is signed with ES384 which starts by taking the sha384 hash of the payload (which is a sha256 hash).

# Encrypted Hashes

When present in COSE_Encrypt, the header parameters registered in this document leak information about the ciphertext.
These parameters SHOULD NOT be present in COSE_Encrypt headers unless this disclosure is acceptable.

# Security Considerations

TODO Security

## Choice of Hash Function

It is RECOMMENDED to align the strength of the chosen hash function to the strength of the chosen signature algorithm.
For example, when signing with ECDSA using P-256 and SHA-256, use SHA-256 to hash the payload.

# IANA Considerations

## COSE Header Algorithm Parameters

IANA is requested to add the following entries to the [COSE Header Algorithm Parameters Registry](https://www.iana.org/assignments/cose/cose.xhtml).

### Payload Hash Algorithm

- Name: payload_hash_alg
- Label: TBD_1
- Value type: int
- Value registry: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
- Description: Hash algorithm used to produce the payload.

### Payload Pre-image Content Type

- Name: payload_preimage_content_type
- Label: TBD_2
- Value type: int
- Value registry: https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats
- Description: The content format associated with the bytes that were hashed to produce the payload.

### Payload Location

- Name: payload_location
- Label: TBD_3
- Value type: tstr
- Value registry: none
- Description: A string or URI as a hint for the location of the payload

--- back

# Implementation Status

Note to RFC Editor: Please remove this section as well as references to {{BCP205}} before AUTH48.

This section records the status of known implementations of the protocol defined by this specification at the time of posting of this Internet-Draft, and is based on a proposal described in {{BCP205}}.
The description of implementations in this section is intended to assist the IETF in its decision processes in progressing drafts to RFCs.
Please note that the listing of any individual implementation here does not imply endorsement by the IETF.
Furthermore, no effort has been spent to verify the information presented here that was supplied by IETF contributors.
This is not intended as, and must not be construed to be, a catalog of available implementations or their features.
Readers are advised to note that other implementations may exist.

According to {{BCP205}}, "this will allow reviewers and working groups to assign due consideration to documents that have the benefit of running code, which may serve as evidence of valuable experimentation and feedback that have made the implemented protocols more mature.
It is up to the individual working groups to use this information as they see fit".

## Transmute Prototype

Organization: Transmute Industries Inc

Name: https://github.com/transmute-industries/transmute

Description: A command line tool and GitHub action for securing software artifacts in GitHub workflows.

Maturity: Prototype

Coverage: The current version ('main') implements this specification and demonstrates hash envelope signing with Azure Key Vault and Google Cloud KMS in addition to supporting local keys.

License: Apache-2.0

Implementation Experience: No interop testing has been done yet. The code works as proof of concept, but is not yet production ready.

Contact: Orie Steele (orie@transmute.industries)

# Acknowledgments
{:numbered="false"}

The following individuals provided input into the final form of the document: Carsten Bormann, Henk Birkholz, Antoine Delignat-Lavaud, Cedric Fournet.
