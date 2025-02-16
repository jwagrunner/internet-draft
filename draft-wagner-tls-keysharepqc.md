---
title: New key share extension for Classic McEliece algorithms
abbrev: keyshare
category: info

docname: draft-wagner-tls-keysharepqc-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: ""
workgroup: "Transport Layer Security"
keyword:
 - key share
 - Classic McEliece
venue:
  group: "Transport Layer Security"
  type: ""
  mail: "tls@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/tls/"
  github: "jwagrunner/internet-draft"
  latest: "https://jwagrunner.github.io/internet-draft/draft-wagner-tls-keysharepqc.html"

author:
 -
    fullname: Jonathan Wagner
    organization: UNC Charlotte
    email: jwagne31@charlotte.edu

normative:

informative:


--- abstract

RFC 8446 is modified to where another key share extension is introduced to accomodate large public keys for post-quantum algorithms including Classic McEliece. A capability is added to where this new key share or the normal key share is in use, depending on the algorithm chosen in a TLS key exchange along with its public key size.


--- middle

# Introduction

Large public key algorithms, including the code-based cryptographic algorithm family Classic McEliece and the Random Linear Code-based Encryption (RLCE) algorithm group, cannot be easily implemented in TLS applications due to the current key share limitations of 65535 bytes. Therefore, this document proposes a new key share that has a higher limit and can be in use for ClientHello and ServerHello messages. A capability is also added to where if a large post-quantum algorithm is requested, the normal key extension will not be constructed or in use. However, if a classical algorithm is requested for key exchange, a normal key share extension is constructed and this new key share extension will not be constructed. Thus enabling the use of large public key post-quantum algorithms to be used in TLS key exchanges, but also presenting it as an alternative option in place of classical algorithms.


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
