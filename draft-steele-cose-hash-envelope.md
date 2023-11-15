---
v: 3
title: "COSE Hash Envelope"
abbrev: "CHE"
cat: std
docname: draft-steele-cose-hash-envelope-latest
stream: IETF
number:
date: 2023
consensus: true
area: "Security"
keyword: Internet-Draft
venue:
  group: "CBOR Object Signing and Encryption"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"
  github: "OR13/draft-steele-cose-hash-envelope"
  latest: "https://OR13.github.io/draft-steele-cose-hash-envelope/draft-steele-cose-hash-envelope.html"

author:
 -
    fullname: Orie Steele
    organization: Transmute
    email: orie@transmute.industries

normative:
  RFC9052: RFC9052
  I-D.ietf-cose-typ-header-parameter: COSE-TYP

informative:

--- abstract

This document defines new COSE header parameters in support of a mechanism that uses hashes of detached payload as the COSE payload, which enables faster signature validation for detached payload as the availability of the original payload is not required for signature validation.
Additionally, hints about the detached payload's content format and availability are defined.

--- middle

# Introduction

COSE defined detached payloads in {{-RFC9052}} in Section 2.
However, in order to verify a detached payload the payload content needs to availble.

This is challenging for large payload, which can not be easily be transported.

This draft addresses this challenge by describing a simply way to protect hashes of payloads while maintaining information about their content type.

## Signed Hashes

### Protected Header

TBD 0 (typ), TBD 1 (payload hash alg) and TBD 2 (content type of the preimage of the payload) MUST be present in the protected header and MUST NOT be present in the unprotected header.

TBD 0 will be assinged by {{-COSE-TYP}}, it represents the content type of the code envelope, which includes the protected header and payload.

~~~~ cbor-diag
{
  / Algorithm                           /
  1: -35,
  / Key identifier                      /
  4: h'75726e3a...32636573',
  / typ of the envelope                 /
  TBD 0: application/hashed+cose
  / Hash algorithm of the payload       /
  TBD 1: 1 / sha-256 /
  / cty of the preimage of the payload  /
  TBD 2: application/jwk+json
}
~~~~

### Attached Payload

The payload MAY be attached.

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

### Detached Payload

The payload MAY be detached.

~~~~ cbor-diag
18(                                 / COSE Sign 1                   /
    [
      h'a4013822...3a616263',       / Protected                     /
      {}                            / Unprotected                   /
      nil,                          / Detached payload              /
      h'15280897...93ef39e5'        / Signature                     /
    ]
)
~~~~

## Encrypted Hashes

Should we define this?

# Conventions and Definitions

{::boilerplate bcp14-tagged}

TBD 0:
  : will be assinged by {{-COSE-TYP}}, it represents the content type of the code envelope, which includes the protected header and payload.

TBD 1:
  : the hash algorithm used to generate the hash about the payload.

TBD 2:
  : the content type of the payload the hash represents.

# Security Considerations

TODO Security

## Choice of Hash Function

It is RECOMMENDED to align the strength of the chosen hash function to the strength of the chosen signature algorithm.
For example, when signing with ECDSA using P-256 and SHA-256, use SHA-256 to hash the payload.

# IANA Considerations

## COSE Header Algorithm Parameters

* Name: payload hash algorithm
* Label: TBD_1
* Value type: int
* Value registry: https://www.iana.org/assignments/named-information/named-information.xhtml
* Description: Hash algorithm used to produce the payload.

## Named Information Hash Algorithm Registry

* Name: SHAKE256
* Label: TBD_2
* Value type: int
* Value registry: https://www.iana.org/assignments/named-information/named-information.xhtml
* Description: SHAKE256 a described in https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf

* Name: ASCON128
* Label: TBD_3
* Value type: int
* Value registry: https://www.iana.org/assignments/named-information/named-information.xhtml
* Description: ASCON128 a described in https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/ascon-spec-round2.pdf

--- back

# Acknowledgments
{:numbered="false"}

The following individuals provided input into the final form of the document: Carsten Bormann, Henk Birkholz, Antoine Delignat-Lavaud, Cedric Fournet.


