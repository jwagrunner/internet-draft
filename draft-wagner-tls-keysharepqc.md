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
title: New key share extension for Classic McEliece algorithms
abbrev: keyshare
category: info

docname: draft-wagner-tls-keysharepqc-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: AREA
workgroup: TLS Working Group
keyword:
 - key share
 - Classic McEliece
venue:
  group: TLS
  type: Working Group
  mail: tls@ietf.org
  arch: https://wiki.ietf.org/group/tls
  github: https://github.com/tlswg
  latest: https://datatracker.ietf.org/wg/tls/documents/

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
