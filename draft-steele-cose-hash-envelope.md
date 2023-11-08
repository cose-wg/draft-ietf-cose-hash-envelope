---
title: "COSE Hash Envelope"
abbrev: "CHE"
category: info

docname: draft-steele-cose-hash-envelope-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "CBOR Object Signing and Encryption"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
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

informative:


--- abstract

This draft defines a mechanism for signing hashes of payloads along with hints about their content format and availability.

--- middle

# Introduction

COSE defined detached payloads in rfc9052#section-2.
However, a detached payload cose sign 1 still requires the payload content to be availble in order to verify.

For large payloads this is a problem. This draft addresses this problem by describing a simply way to sign hashes of large payloads while maintaining information about their content type.

## Usage

### Protected Header
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


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Security Considerations

TODO Security

## Choice of Hash Function

Choose a good one.

# IANA Considerations

#### COSE Header Algorithm Parameters

* Name: payload hash algorithm
* Label: TBD_1
* Value type: int
* Value registry: https://www.iana.org/assignments/named-information/named-information.xhtml
* Description: Hash algorithm used to produce the payload.

--- back

# Acknowledgments
{:numbered="false"}

The following individuals provided input into the final form of the document: Carsten Bormann, Henk Birkholz, Antoine Delignat-Lavaud, Cedric Fournet.


