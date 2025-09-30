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
  email: orie@or13.io

- fullname: Steve Lasker
  email: stevenlasker@hotmail.com

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
  RFC7252: COAP
  RFC8610: CDDL
  RFC9052: COSE
  RFC9110: HTTP-Semantics

informative:
  BCP205:

entity:
  SELF: "RFCthis"
  br: "&#x2028;"

--- abstract

This document defines new COSE header parameters for signaling a payload as an output of a hash function.
This mechanism enables faster validation as access to the original payload is not required for signature validation.
Additionally, hints of the detached payload's content format and availability are defined providing references to optional discovery mechanisms that can help to find original payload content.

--- middle

# Introduction

COSE defined detached payloads in Section 2 of {{-COSE}}, using `nil` as the payload.
In order to verify a signature over a COSE_Sign1, the signature checker requires access to the payload content.
Hashes are already used on a regular basis as identifiers for payload data, such as documents or software components.
As hashes typically are smaller than the payload data they represent, they are simpler to transport.
Additional hints in the protected header ensure cryptographic agility for the hashing and signing algorithms.
Hashes and other identifiers are commonly used as hints to discover and distinguish resources.
Using a hash as an identifier for a resource has the advantage of enabling integrity checking.
In some applications, such as remote signing procedures, conveyance of hashes instead original payload content reduce transmission time and costs.

# Terminology

{::boilerplate bcp14-tagged}

The terms COSE and CDDL are defined in {{-COSE}} and {{-CDDL}} respectively.

# Header Parameters {#param-spec}

This document specifies the following new header parameters commonly used alongside hashes to identify resources:

258:
  : the hash algorithm used to produce the payload.

259:
  : the content type of the bytes that were hashed (preimage) to produce the payload, given as a content-format number ({{Section 12.3 of RFC7252}}) or as a media-type name optionally with parameters ({{Section 8.3 of RFC9110}}).

260:
  : an identifier enabling retrieval of the original resource (preimage) identified by the payload.

# Hash Envelope CDDL

~~~ cddl
Hash_Envelope = #6.18(Hash_Envelope_as_COSE_Sign1)

Hash_Envelope_as_COSE_Sign1 = [
    protected: bstr .cbor Hash_Envelope_Protected_Header,
    unprotected: Hash_Envelope_Unprotected_Header,
    payload: bstr / nil,
    signature: bstr
]

Hash_Envelope_Protected_Header = {
    ? &(alg: 1) => int,
    &(payload_hash_alg: 258) => int
    ? &(payload_preimage_content_type: 259) => uint / tstr
    ? &(payload_location: 260) => tstr
    * (int / tstr) => any
}

Hash_Envelope_Unprotected_Header = {
    * (int / tstr) => any
}
~~~

- Label `1` (alg) Cryptographic algorithm to use
- Label `258` (payload hash alg) MUST be present in the protected header and MUST NOT be present in the unprotected header.
- Label `259` (content type of the preimage of the payload) MAY be present in the protected header and MUST NOT be present in the unprotected header.
- Label `260` (payload_location) MAY be present in the protected header and MUST NOT be present in the unprotected header.
- Label `3` (content_type) MUST NOT be present in the protected or unprotected headers.

Label `3` is easily confused with label `259` payload_preimage_content_type.
The difference between content_type (3) and payload_preimage_content_type (259) is content_type is used to identify the content format associated with payload, whereas payload_preimage_content_type is used to identify the content format of the bytes which are hashed to produce the payload.

Profiles that rely on this specification MAY choose to mark 258, 259, 260 (or other header parameters) critical, see {{Section C.1.3 of RFC9052}} for more details.

Envelope Extended Diagnostic Notation ({{Appendix G of RFC8610}}).

The following informative example demonstrates how to construct a hash envelope for a resource already commonly referenced by its hash.

~~~~ cbor-diag
18([ # COSE_Sign1
  <<{
    / signature alg   / 1: -35, # ES384
    / key identifier  / 4: h'75726e3a...32636573',
    / COSE_Sign1 type / 16: "application/example+cose",
    / hash algorithm  / 258: -16, # sha256
    / media type      / 259: "application/spdx+json",
    / location        /
         260: "https://sbom.example/.../manifest.spdx.json"
  }>>
  / unprotected / {},
  / payload     / h'935b5a91...e18a588a',
         # As seen in manifest.spdx.json.sha256
  / signature   / h'15280897...93ef39e5'
         # ECDSA Signature with SHA 384 and P-384
])
~~~~

In this example, an SPDX software bill of materials (SBOM) in JSON format is already commonly identified by its SHA256 hash.
For example, some tooling generates a file, such as `manifest.spdx.json.sha256`, which contains the SHA256 hash of the corresponding `manifest.spdx.json` file.

The content type for `manifest.spdx.json` is already well known as `application/spdx+json`, and is [registered with IANA](https://www.iana.org/assignments/media-types/application/spdx+json).

The full JSON SBOM is available at a URL, such as `https://sbom.example/.../manifest.spdx.json`.

The payload of this COSE_Sign1 is the SHA256 hash of the `manifest.spdx.json`, which is typically found in an adjacent file (`manifest.spdx.json.sha256`).

The type of this COSE_Sign1 is `application/example+cose`, but other types may be used to establish more specific media types for signatures of hashes.

The signature is produced using ES384 which means using ECDSA with SHA384 hash function and P-384 elliptic curve.

This example is chosen to highlight that an existing system may use a hash algorithm such as sha256.
This hash becomes the payload of a COSE-Sign1.
When signed with a signature algorithm that is parameterized via a hash function, such as ECDSA with SHA384, the to be signed structure is as described in Section 4.4 of RFC9052.

The resulting signature is computed over the protected header and payload, providing integrity and authenticity for the hash algorithm, content type and location of the associated resource, in this case a software bill of materials.

# Security Considerations

## Choice of Hash Function

It is RECOMMENDED to align the strength of the chosen hash function to the strength of the chosen signature algorithm.
For example, when signing with ECDSA using P-256 and SHA-256, use SHA-256 to hash the payload.
Note that when using a pre-hash algorithm, the algorithm SHOULD be registered in the IANA COSE Algorithms registry, and should be distinguishable from non-pre hash variants that may also be present.
The approach this specification takes is just one way to perform application agnostic pre-hashing, meaning the pre hashing is not done with binding or consideration for a specific application context, while performing application (COSE) specific signing, meaning the to be signed bytes include the COSE structures necessary to distinguish a COSE signature from other digital signature formats.

## Encrypted Hashes

When present in COSE_Encrypt, the header parameters registered in this document leak information about the ciphertext.
These parameters SHOULD NOT be present in COSE_Encrypt headers unless this disclosure is acceptable.

When present in a protected header, the semantics are the same as for a COSE_Sign1: decrypted payload is expected to be the output of the hash function specified in the protected header.

# IANA Considerations

## COSE Header Parameters

IANA is requested to add the COSE header parameters defined in {{param-spec}}, as listed in {{iana-header-params}}, to the "COSE Header Parameters" registry {{!IANA.cose_header-parameters}}, in the 'Integer values from 256 to 65535' range ('Specification Required' Registration Procedure).

| Name                    | Label | Value Type  | (1)    | Description                                                                                                                       | Reference             |
|-------------------------|-------|-------------|--------|-----------------------------------------------------------------------------------------------------------------------------------|-----------------------|
| `payload-hash-alg`      | 258 | int         | (2)    | The hash algorithm used to produce the payload of a COSE_Sign1                                                                    | {{&SELF}}, {{param-spec}} |
| `preimage-content-type` | 259 | uint / tstr | (3)    | The content-format number or content-type (media-type name) of data that has been hashed to produce the payload of the COSE_Sign1 | {{&SELF}}, {{param-spec}} |
| `payload-location`      | 260 | tstr        | (none) | The string or URI hint for the location of the data hashed to produce the payload of a COSE_Sign1                                 | {{&SELF}}, {{param-spec}} |
{: #iana-header-params title="Newly registered COSE Header Parameters
&br;(1): Value Registry
&br;(2): https://www.iana.org/assignments/cose/cose.xhtml#algorithms
&br;(3): https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#content-formats"}

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

Implementation Experience: No interop testing has been done yet.
The code works as proof of concept, but is not yet production ready.

Contact: Orie Steele (orie@or13.io)

## DataTrails Preview

Organization: DataTrails

Name: https://github.com/datatrails/scitt-action

Description: A GitHub Action for registering statements about artifacts on a transparency service.

Maturity: Preview

Coverage: The current version ('main') implements this specification and demonstrates hash envelope signing with DataTrails implementation of SCITT.

License: MIT

Implementation Experience: Interop testing has been performed between DigiCert and DataTrails.
The code works as proof of concept, but is not yet production ready.

Contact: Steve Lasker (stevenlasker@hotmail.com)

## DigiCert Preview

Organization: DigiCert

Name: https://github.com/digicert/scitt-action

Description: A GitHub Action for remote signing and registering statements about artifacts on a transparency service.

Maturity: Preview

Coverage: The current version ('main') implements this specification and demonstrates hash envelope signing with DigiCert Software Trust Manager.

License: MIT

Implementation Experience: Interop testing has been performed between DigiCert and DataTrails.
The code works as proof of concept, but is not yet production ready.

Contact: Corey Bonnell (Corey.Bonnell@digicert.com)

# Acknowledgments
{:numbered="false"}

The following individuals provided input into the final form of the document: Carsten Bormann, Henk Birkholz, Antoine Delignat-Lavaud, Cedric Fournet.
