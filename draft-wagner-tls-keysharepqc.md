---
title: New Key Share Extension for Classic McEliece Algorithms
abbrev: keyshare
category: std

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
    ins: J. Wagner
    name: Jonathan Wagner
    org: UNC Charlotte
    street: 9201 University City Blvd
    city: Charlotte, NC
    code: 28223
    country: USA
    email: jwagne31@charlotte.edu
  -
    ins: Y. Wang
    name: Yongge Wang
    org: UNC Charlotte
    street: 9201 University City Blvd
    city: Charlotte, NC
    code: 28223
    country: USA
    email: yongge.wang@charlotte.edu

normative:
  RFC8446:
    target: https://datatracker.ietf.org/doc/html/rfc8446
    title: "The Transport Layer Security (TLS) Protocol Version 1.3"
    author:
      ins: E. Rescorla
      name: Eric Rescorla
    date: 2018
  TLSE:
    target: https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
    title: "Transport Layer Security (TLS) Extensions"
    author:
      org: Internet Assigned Numbers Authority
    date: 2024
  TLSP:
    target: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
    title: "Transport Layer Security (TLS) Parameters"
    author:
      org: Internet Assigned Numbers Authority
    date: 2025

informative:
  RMC:
    target: https://ipnpr.jpl.nasa.gov/progress_report2/42-44/44N.PDF
    title: "A Public-Key Cryptosystem Based On Algebraic Coding Theory"
    author:
      ins: R. McEliece
      name: R. J. McEliece
    date: 1978
  CMC:
    target: https://classic.mceliece.org/impl.html
    title: "Classic McEliece: Implementation"
    author:
     -
      ins: D. Bernstein
      name: Daniel J. Bernstein
     -
      ins: T. Chou
      name: Tung Chou
     -
      ins: C. Cid
      name: Carlos Cid
     -
      ins: J. Gilcher
      name: Jan Gilcher
     -
      ins: T. Lange
      name: Tanja Lange
     -
      ins: V. Maram
      name: Varun Maram
     -
      ins: I. von Maurich
      name: Ingo von Maurich
     -
      ins: R. Misoczki
      name: Rafael Misoczki
     -
      ins: R. Niederhagen
      name: Ruben Niederhagen
     -
      ins: E. Persichetti
      name: Edoardo Persichetti
     -
      ins: C. Peters
      name: Christiane Peters
     -
      ins: N. Sendrier
      name: Nicolas Sendrier
     -
      ins: J. Szefer
      name: Jakub Szefer
     -
      ins: C. Tjhai
      name: Cen Jung Tjhai
     -
      ins: M. Tomlinson
      name: Martin Tomlinson
     -
      ins: W. Wang
      name: Wen Wang
    date: 2024
  RLCE:
    target: https://eprint.iacr.org/2017/206.pdf
    title: "Quantum Resistant Public Key Encryption Scheme RLCE and IND-CCA2 Security for McEliece Schemes"
    author:
      ins: Y. Wang
      name: Yongge Wang
    date: 2017
  NISTPQC:
    target: https://csrc.nist.gov/projects/post-quantum-cryptography/round-4-submissions
    title: "Post-Quantum Cryptography: Round 4 Submissions"
    author:
      org: NIST
    date: 2025
  OQSCMC:
    target: https://openquantumsafe.org/liboqs/algorithms/kem/classic_mceliece
    title: "liboqs / Algorithms / Classic McEliece"
    author:
      org: Open Quantum Safe
    date: 2024
  MINEXT:
    target: https://github.com/jwagrunner/openssl/blob/master/ssl/statem/statem_srvr.c#L1650
    title: "ssl/statem/statem_srvr.c#L1650"
    author:
      ins: J. Wagner
      name: Jonathan Wagner
    date: 2024
  CONSTEXT:
    target: https://github.com/jwagrunner/openssl/blob/master/ssl/statem/statem_srvr.c#L1211
    title: "ssl/statem/statem_srvr.c#L1211"
    author:
      ins: J. Wagner
      name: Jonathan Wagner
    date: 2024
  MODCOL:
    target: https://github.com/jwagrunner/openssl/blob/master/ssl/statem/extensions.c#L652C9-L663C9
    title: "ssl/statem/extensions.c#L652C9-L663C9"
    author:
      ins: J. Wagner
      name: Jonathan Wagner
    date: 2024
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
  OpenSSL:
    target: https://github.com/jwagrunner/openssl
    title : "openssl"
    author:
     -
      ins: J. Wagner
      name: Jonathan Wagner
     -
      ins: Y. Wang
      name: Yongge Wang
    date: 2025
--- abstract

RFC 8446 is modified to where another key share extension is introduced to accommodate both public keys and ciphertexts in ClientHello and ServerHello messages for post-quantum algorithms that have large public keys, including the code-based cryptographic schemes the Classic McEliece family and the RLCE algorithm group.

--- middle

# Introduction

Large public key algorithms, including the code-based cryptographic algorithm family Classic McEliece (see [RMC], [CMC], and [OQSCMC]) and the Random Linear Code-based Encryption (RLCE) algorithm group (see [RLCE]), cannot be easily implemented in TLS 1.3 due to the current key share limitations of 65535 bytes. It is important to consider such uses of algorithms given that Classic McEliece is a Round 4 algorithm submitted in the NIST standardization process (see [NISTPQC]). Therefore, this document proposes a new key share that has a higher limit and is utilized in ClientHello and ServerHello messages, which is a modification of [RFC8446]. For example, if a large post-quantum algorithm is requested in a TLS 1.3 key exchange, this new key share extension will be constructed but the original key share extension will not be constructed. However, if a classical algorithm is requested for key exchange, a normal key share extension is constructed and this new key share extension will not be constructed. Thus enabling the use of large public key post-quantum algorithms to be used in TLS 1.3 key exchanges, and also presenting them as an alternative option to replace classical algorithms for future protection against the threat of attackers in possession of powerful quantum computers that will break classical encryption.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# New Key Share Extension

Based on the key share extension from RFC8446 is introduced a new key share extension, key_share_pqc. This is reflected in this document and is represented as KeyShareEntryPQC below, based off of the existing KeyShareEntry from [RFC8446]. However this is modified along with the existing KeyShareEntry structure to include case statements to test if the key exchange algorithm chosen in a TLS 1.3 connection belongs to either the Classic McEliece family or RLCE algorithm group, and if it is, then KeyShareEntryPQC is constructed and KeyShareEntry is not constructed. If the opposite is true, where the key exchange algorithm does not belong to either group, then KeyShareEntryPQC is not constructed but KeyShareEntry is constructed. Note that the key_exchange field is expanded in KeyShareEntryPQC to accomodate a large public key that is greater than 65535 bytes:

<figure><artwork>

    struct {
       NamedGroup group;
       select (NameGroup.group) {
       case classicmceliece348864 | classicmceliece348864f | classicmceliece460896
       | classicmceliece460896f | classicmceliece6688128 | classicmceliece6688128f
       | classicmceliece6960119 | classicmceliece6960119f | classicmceliece8192128
       | classicmceliece8192128f
       | rlcel1 | rlcel3 | rlcel5 :
             break;
       default :
             opaque key_exchange<1..2^16-1>;
       }
    } KeyShareEntry;

    struct {
       NamedGroup group;
       select (NamedGroup.group) {
       case classicmceliece348864 | classicmceliece348864f | classicmceliece460896
       | classicmceliece460896f | classicmceliece6688128 | classicmceliece6688128f
       | classicmceliece6960119 | classicmceliece6960119f | classicmceliece8192128
       | classicmceliece8192128f
       | rlcel1 | rlcel3 | rlcel5 :
             opaque key_exchange<1..2^24-1>;
       default :
             break;
       }
    } KeyShareEntryPQC

</artwork></figure>

This is then applied to the existing KeyShareClientHello structure, which originates from RFC 8446, that now contains an additional field for KeyShareEntryPQC:

<figure><artwork>

    struct {
       KeyShareEntry client_shares<0..2^16-1>;
       KeyShareEntryPQC client_shares<0..2^24-1>;
    } KeyShareClientHello;

</artwork></figure>

Since the KeyShareClientHello needs to be expanded to accomodate for the KeyShareEntryPQC struct, the same applies to the existing Extension struct, originated as well from RFC 8446 but extension_data is now expanded:

<figure><artwork>

    struct {
      ExtensionType extension_type;
      opaque extension_data<0..2^24-1>;
    } Extension;

</artwork></figure>

Since there is a new key share extension to accomodate keys larger than the 65535 Byte limit (KeyShareEntryPQC), this is reflected in the existing ExtensionType structure from RFC 8446 where this is the new type that holds a value of 63, key_share_pqc:

<figure><artwork>

    enum {
            server_name(0),                             /* RFC 6066 */
            max_fragment_length(1),                     /* RFC 6066 */
            status_request(5),                          /* RFC 6066 */
            supported_groups(10),                       /* RFC 8422, 7919 */
            signature_algorithms(13),                   /* RFC 8446 */
            use_srtp(14),                               /* RFC 5764 */
            heartbeat(15),                              /* RFC 6520 */
            application_layer_protocol_negotiation(16), /* RFC 7301 */
            signed_certificate_timestamp(18),           /* RFC 6962 */
            client_certificate_type(19),                /* RFC 7250 */
            server_certificate_type(20),                /* RFC 7250 */
            padding(21),                                /* RFC 7685 */
            pre_shared_key(41),                         /* RFC 8446 */
            early_data(42),                             /* RFC 8446 */
            supported_versions(43),                     /* RFC 8446 */
            cookie(44),                                 /* RFC 8446 */
            psk_key_exchange_modes(45),                 /* RFC 8446 */
            certificate_authorities(47),                /* RFC 8446 */
            oid_filters(48),                            /* RFC 8446 */
            post_handshake_auth(49),                    /* RFC 8446 */
            signature_algorithms_cert(50),              /* RFC 8446 */
            key_share(51),                              /* RFC 8446 */
            key_share_pqc(63),
            (65535)
        } ExtensionType;

</artwork></figure>

Since the "extension_data" field will be much larger for a KeyShareClientHello that contains a large public key that is greater than the previously defined 65535 byte limit, an example being a Classic McEliece public key, the server must be able to handle this circumstance when receiving the ClientHello message. One way is to compare the value for a packet that contains extensions including a large public key from the ClientHello message to a macro constant (for example,  CLIENT_HELLO_MIN_EXT_LENGTH as defined in this introduced TLS implementation in this paper, see [MINEXT] and [CONSTEXT]) and if this packet value is longer than this constant, the server will change the way it normally handles all of the extensions. This constant could be easily modified in the aformentioned TLS OpenSSL implementation. The process of how the server collects the extensions from a ClientHello message must also be modified, as the server must be able to process the new key share extension of Type 63 differently than the other extensions, should the server see this inside a ClientHello message. For example, see [MODCOL].

The ServerHello message is modified as well originating from RFC 8446:

<figure><artwork>

struct {
    KeyShareEntry server_share;
    KeyShareEntryPQC server_sharePQC;
} KeyShareServerHello;

</artwork></figure>

# NamedGroup Addition for Classic McEliece and RLCE

The NIDS for Classic McEliece and RLCE algorithms are added below in the NamedGroup struct that originates from RFC 8446:

<figure><artwork>

    enum {

              /* Elliptic Curve Groups (ECDHE) */
              secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
              x25519(0x001D), x448(0x001E),

              /* Finite Field Groups (DHE) */
              ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
              ffdhe6144(0x0103), ffdhe8192(0x0104),

              /* Reserved Code Points */
              ffdhe_private_use(0x01FC..0x01FF),
              ecdhe_private_use(0xFE00..0xFEFF),
              (0xFFFF)

              /* Classic McEliece family */
              classicmceliece348864(0x002A), classicmceliece348864f(0x002B), classicmceliece460896(0x002C),
              classicmceliece460896f(0x002D), classicmceliece6688128(0x002E), classicmceliece6688128f(0x002F),
              classicmceliece6960119(0x0030), classicmceliece6960119f(0x0031), classicmceliece8192128(0x0032),
              classicmceliece8192128f(0x0033)

              /* RLCE algorithm group */
              rlcel1(0x0034), rlcel3(0x0035), rlcel5(0x0036)
          } NamedGroup;

</artwork></figure>

# TLS Implementation

A TLS implementation exists that tests the use of a new key share extension for both the ClientHello and ServerHello message, as described above, is implemented for OpenSSL. It can be accessed here: [OpenSSL].

# Summary of Changes from RFC 8446

A new structure is introduced of KeyShareEntryPQC along with modifications of existing structures including KeyShareEntry, NamedGroup, Extension, ExtensionType, KeyShareClientHello, and KeyShareServerHello. Adding a new ExtensionType of key_share_pqc allows for the addition of this new structure of KeyShareEntryPQC, which is based on the existing KeyShareEntry, but key_exchange has been expanded and select statements are added to both structures which depend on the NamedGroup.group being called in a TLS connection for key exchange. This new KeyShareEntryPQC will now also appear in existing structures of KeyShareClientHello and KeyShareServerHello. Thus the extension_data is expanded in the existing Extension structure.


# Security Considerations

Larger ClientHello messages can cause TLS connections to be dropped and for TLS handshakes to be broken, as evidenced by the inclusion of post-quantum cryptography in applications of Google Chrome 124 and Microsoft Edge 124, specifically the use of Kyber768 for key agreement. See [GCTLS]. A possible workaround includes updating web servers if receiving an error with TLS/SSL if Kyber is utlized through Chrome or Firefox. See [KASPPQC].

# IANA Considerations

The new key share proposed in this document key_share_pqc, along with its value of 63, needs to be updated in the registry specified for TLS ExtensionType Values. See [TLSE]. The registry for TLS Supported Groups will need to have the proper values assigned to the Classic McEliece family with the entries of 42-51 and the RLCE algorithm group with 52-54. See [TLSP].


--- back
