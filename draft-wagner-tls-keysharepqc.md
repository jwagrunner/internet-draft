---
title: New Key Share Extension for Classic McEliece Algorithms
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

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# New Key Share Extension

Based on the key share extension from RFC8446 is introduced a new key share extension, key_share_pqc. This is reflected in this document and is represented as KeyShareEntryPQC below, based off of the existing KeyShareEntry from RFC8446. However this is modified along with the existing KeyShareEntry structure to include case statements to test if key exchange algorithm chosen in a TLS connection belongs to either the Classic McEliece family or RLCE algorithm group, and if it is, then KeyShareEntryPQC is constructed and KeyShareEntry is not constructed. If the opposite is true, where the key exchange algorithm does not belong to either group, then KeyShareEntryPQC is not constructed but KeyShareEntry is constructed. Note that the key_exchange field is expanded in KeyShareEntryPQC to accomodate a large public key that is greater than 65535 bytes:

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

This is then applied to the existing KeyShareClientHello structure, when originates from RFC8446, which now contains an additional field for KeyShareEntryPQC:

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

Since there is a new key share extension to accomodate keys larger than the 65535 limit (KeyShareEntryPQC), this is reflected in the existing ExtensionType structure from RFC 8446 where this is the new type that holds a value of 63, key_share_pqc:

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

Since the "extension_data" field will be much larger for a KeyShareClientHello that contains a large public key that is greater than the previously defined 65535 byte limit, an example being a Classic McEliece public key, the server must be able to handle this circumstance. One way is to compare the value for the length of extensions in a ClientHello message to a macro constant (for example,  CLIENT_HELLO_MIN_EXT_LENGTH as defined in link) and if extension length is longer than this constant, the server will change the way it normally handles all of the extensions. This constant can be defined as a value representing the lowest possible value for a ClientHello message's extension length, if it were to contain a public key that is larger than the 65535 byte limit (for example, defining this constant value to be 188168 bytes which would be the extension length (plus three bytes) if the ClientHello message contains a RLCE algorithm that has a 188001 public key, where this constant could be easily modified and lowered in the TLS implementation OpenSSL, should there be a public key for a post-quantum algorithm lower than this 188001 byte value, but still higher than 65535 bytes).

The process of how the server collects the extensions from a ClientHello message must also be modified, as the server must be able to process the new key share extension of Type 63 differently than the other extensions, should the server see this inside a ClientHello message.

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
    </br>
              /* Elliptic Curve Groups (ECDHE) */
              secp256r1(0x0017), secp384r1(0x0018), secp521r1(0x0019),
              x25519(0x001D), x448(0x001E),
    </br>
              /* Finite Field Groups (DHE) */
              ffdhe2048(0x0100), ffdhe3072(0x0101), ffdhe4096(0x0102),
              ffdhe6144(0x0103), ffdhe8192(0x0104),
     </br>
              /* Reserved Code Points */
              ffdhe_private_use(0x01FC..0x01FF),
              ecdhe_private_use(0xFE00..0xFEFF),
              (0xFFFF)
     </br>
              /* Classic McEliece family */
              classicmceliece348864(0x0235), classicmceliece348864f(0x0236), classicmceliece460896(0x0237),
              classicmceliece460896f(0x0239), classicmceliece6688128(0x0247), classicmceliece6688128f(0x0248),
              classicmceliece6960119(0x0249), classicmceliece6960119f(0x024A), classicmceliece8192128(0x024B),
              classicmceliece8192128f(0x024C)
     </br>
              /* RLCE algorithm group */
              rlcel1(0x024D), rlcel3(0x024E), rlcel5(0x024F)
          } NamedGroup;

</artwork></figure>

# Summary of Changes from RFC 8446

A new structure is introduced of KeyShareEntryPQC along with modifications of existing structures including KeyShareEntry, NamedGroup, Extension, ExtensionType, KeyShareClientHello, and KeyShareServerHello. Adding a new ExtensionType of key_share_pqc allows for the addition of this new structure of KeyShareEntryPQC, which is based on the existing KeyShareEntry, but key_exchange has been expanded and select statements are added to both structures which depend on the NamedGroup.group being called in a TLS connection for key exchange. This new KeyShareEntryPQC will now also appear in existing structures of KeyShareClientHello and KeyShareServerHello. Thus the extension_data is expanded in the existing Extension structure.


# Security Considerations

Larger ClientHello messages can cause TLS connections to be dropped and for TLS handshakes to be broken, as evidenced by the inclusion of post-quantum cryptography in applications of Google Chrome 124 and Microsoft Edge 124, specifically the use of Kyber768 for key agreement. See [GCTLS]. A possible workaround includes updating web servers if receiving an error with TLS/SSL if Kyber is utlized through Chrome or Firefox. See [KASPPQC].

# IANA Considerations

The new key share proposed in this document key_share_pqc, along with its value of 63, needs to be updated in the registry specified for TLS ExtensionType Values. See [TLSE]. The registry for TLS Supported Groups will need to have the proper values assigned to the Classic McEliece family with the entries of 42-51 and the RLCE algorithm group with 52-54. See [TLSP].


--- back
