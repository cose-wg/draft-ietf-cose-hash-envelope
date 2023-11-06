---
###
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is "draft-<yourname>-<workgroup>-<name>.md".
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
title: "COSE Hash Envelope"
abbrev: "CHE"
category: info

docname: draft-steele-cose-hash-envelope-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: Security
workgroup: COSE
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
venue:
  group: WG
  type: Working Group
  mail: WG@example.com
  arch: https://example.com/WG
  github: OR13/draft-steele-cose-hash-envelope
  latest: https://example.com/LATEST

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


# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

The following individuals provided input into the final form of the document: Carsten Bormann, Henk Birkholz, Antoine Delignat-Lavaud, Cedric Fournet.


