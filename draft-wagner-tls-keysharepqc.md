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
  TLSE:
    author:
      org: Internet Assigned Numbers Authority
    title: Transport Layer Security (TLS) Extensions
    date: 2024-12
    target: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    
informative:
  GCTLS:
    target: https://www.bleepingcomputer.com/news/security/google-chromes-new-post-quantum-cryptography-may-break-tls-connections/
    title: "Google Chrome's new post-quantum cryptography may break TLS connections"
    author:
      ins: S. Gatlan
      name: Sergiu Gatlan
    date: 2024
  KASPPQC:
    target: https://www.kaspersky.com/blog/postquantum-cryptography-2024-implementation-issues/52095/
    title: "Where and how post-quantum cryptography is being used in 2024"
    author:
      ins: S. Kaminsky
      name: Stan Kaminsky
    date: 2024

--- abstract

RFC 8446 is modified to where another key share extension is introduced to accomodate large public keys for post-quantum algorithms including Classic McEliece. A capability is added to where this new key share or the normal key share is in use, depending on the algorithm chosen in a TLS key exchange along with its public key size.


--- middle

# Introduction

Large public key algorithms, including the code-based cryptographic algorithm family Classic McEliece and the Random Linear Code-based Encryption (RLCE) algorithm group, cannot be easily implemented in TLS applications due to the current key share limitations of 65535 bytes. Therefore, this document proposes a new key share that has a higher limit and can be in use for ClientHello and ServerHello messages. A capability is also added to where if a large post-quantum algorithm is requested, the normal key extension will not be constructed or in use. However, if a classical algorithm is requested for key exchange, a normal key share extension is constructed and this new key share extension will not be constructed. Thus enabling the use of large public key post-quantum algorithms to be used in TLS key exchanges, but also presenting it as an alternative option in place of classical algorithms.

# Summary of Changes from RFC 8446

A new structure is introduced of KeyShareEntryPQC along with modifications of existing structures including KeyShareEntry, NamedGroup, Extension, ExtensionType, KeyShareClientHello, and KeyShareServerHello. Adding a new ExtensionType of key_share_pqc allows for the addition of this new structure of KeyShareEntryPQC, which is based on the existing KeyShareEntry, but key_exchange has been expanded and select statements are added to both structures which depend on the NamedGroup.group being called in a TLS connection for key exchange. This new KeyShareEntryPQC will now also appear in existing structures of KeyShareClientHello and KeyShareServerHello. Thus the extension_data is expanded in the existing Extension structure.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

Larger ClientHello messages can cause TLS connections to be dropped and for TLS handshakes to be broken, as evidenced by the inclusion of post-quantum cryptography in applications of Google Chrome 124 and Microsoft Edge 124, specifically the use of Kyber768 for key agreement. See [GCTLS]. A possible workaround includes updating web servers if receiving an error with TLS/SSL if Kyber is utlized through Chrome or Firefox. See [KASPPQC].

# IANA Considerations

The new key share proposed in this document key_share_pqc, along with its value of 63, needs to be updated in the registry specified for TLS ExtensionType Values. See [TLSE].


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
