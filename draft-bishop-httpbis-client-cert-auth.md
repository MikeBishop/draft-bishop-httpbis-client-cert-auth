---
title: "Client Certificate Authentication in HTTP"
abbrev: "Client Cert Auth"
category: std

docname: draft-bishop-httpbis-client-cert-auth-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "HTTP"
keyword:
 - client certificate
 - http authentication
 - exported authenticator
venue:
  group: "HTTP"
  type: "Working Group"
  mail: "ietf-http-wg@w3.org"
  github: "MikeBishop/client-cert-auth"
  latest: "https://MikeBishop.github.io/client-cert-auth/draft-bishop-httpbis-client-cert-auth.html"

author:
 -
    fullname: Mike Bishop
    organization: Akamai Technologies
    email: mbishop@evequefou.be

normative:
  BASE64:
    RFC4648

informative:


--- abstract

A use of TLS Exported Authenticators is described which enables HTTP servers to
request and HTTP clients to offer certificate-based credentials after the
connection is established. The means by which these credentials are used with
requests is defined.

--- middle

# Introduction

Many HTTP {{!HTTP=RFC9110}} servers have authentication requirements for the
resources they serve. Using client certificates for authentication presents a
unique challenge because of the interaction with the underlying TLS layer.

Servers that use client certificates to authenticate users might request client
authentication during or immediately after the TLS handshake.  However, if not
all users or resources need certificate-based authentication, a request for a
certificate has the unfortunate consequence of triggering the client to seek a
certificate, possibly requiring user interaction, network traffic, or other
time-consuming activities. During this time, the connection is stalled in many
implementations. Such a request can result in a poor experience, particularly
when sent to a client that does not expect the request.

The TLS 1.3 CertificateRequest can be used by servers to give clients hints
about which certificate to offer.  Servers that rely on certificate-based
authentication might request different certificates for different resources.
Such a server cannot use contextual information about the resource to construct
an appropriate TLS CertificateRequest message during the initial handshake.

Consequently, client certificates are requested at connection establishment time
only in cases where all clients are expected or required to have a single
certificate that is used for all resources. Many forms of HTTP authentication
are reactive, that is, credentials are requested in response to the client
making a request.

TLS 1.2 {{?TLS12=RFC5246}} enabled this by permitting the server to request a
new TLS handshake, in which the server will request the client's certificate.
While this works for HTTP/1.1, HTTP/2 {{?HTTP2=RFC9113}} prohibits renegotiation
after any application data has been sent. This completely blocks reactive
certificate authentication in HTTP/2 using TLS 1.2.

TLS 1.3 {{?TLS=RFC8446}} introduces a new client authentication mechanism that
allows for clients to authenticate after the handshake has been completed. For
the purposes of authenticating an HTTP request, this is functionally equivalent
to renegotiation.  Unfortunately, many TLS stacks do not support post-handshake
authentication, so servers cannot assume its availability at all clients.

In addition, an important part of the HTTP/1.1 exchange is that the client is
able to easily identify the request that caused the TLS renegotiation.  The
client is able to assume that the next unanswered request on the connection is
responsible.  The HTTP stack in the client is then able to direct the
certificate request to the application or component that initiated that request.
This ensures that the application has the right contextual information for
processing the request.

In newer mappings of HTTP, a client can have multiple outstanding requests.
Without some sort of correlation information, a client is unable to identify
which request caused the server to request a certificate. An exchange purely at
the TLS layer is unable to provide such information using existing mechanisms.

## TLS Exported Authenticators

Exported Authenticators {{!ExpAuth=RFC9261}} provide a way to authenticate one
party of a TLS connection to its peer using authentication messages created
after the session has been established. This allows the client to prove
ownership of additional identities at any time after the handshake has
completed. This proof of authentication can be exported and transmitted as part
of an application-layer protocol, but is bound to the TLS connection within
which it was generated.

{{ExpAuth}} defines multiple modes for using an exported authenticator. In the
"Client Authentication" mode, the server generates an authenticator request
which encodes an unpredictable `request_context` and a description of the
desired credential. The client responds by generating an authenticator
containing the requested credential, which the server is able to validate.

If the exchange is successful, the server has the same level of assurance of the
client's identity as if the certificate had been requested and provided in the
TLS handshake.


## Conventions and Definitions

{::boilerplate bcp14-tagged}

# The ExportedAuthenticator Authentication Scheme

This document defines the "ExportedAuthenticator" HTTP authentication scheme.
User agents possess an X.509 certificate type as defined in {{!TLS}}.
Alternative certificate formats (such as Raw Public Keys as described in
{{?RFC7250}}) are not supported in this version of the specification and their
use in this context has not yet been analyzed.

All authentication parameters are encoded using base64url (see {{Section 5 of
BASE64}}) without quotes and without padding. In other words, these byte
sequence authentication parameters values MUST NOT include any characters other
then ASCII letters, digits, dash and underscore.

## Challenge

As described in {{Section 11.3 of HTTP}}, a 401 (Unauthorized) or 407 (Proxy
Authentication Required) response message is used by an origin server or proxy
respectively to challenge the authorization of a user agent. Such a response
includes a WWW-Authenticate or Proxy-Authenticate header field containing at
least one challenge applicable to the requested resource.

A server or proxy which will accept exported authenticators as a valid
authentication type includes a challenge with the scheme
"ExportedAuthenticator" and a single authentication parameter "req" containing
an authenticator request produced by calling the "request" API described in
{{Section 7.1 of ExpAuth}}, encoded using base64url.

The `certificate_request_context` used in generating the request MUST uniquely
identify the set of extensions requested from the client and MUST contain
additional random input which cannot be predicted by the client. A server MAY
reuse the resulting challenge multiple times in response to multiple requests
arriving over a short period of time, but MUST NOT continue to use the same
context value over a long period of time.

## Response

After receiving a challenge in response to a request, a client that wishes to
authenticate itself can include an Authorization or Proxy-Authorization header
field in a subsequent request.

The client passes the desired identity and the authenticator request generated
by the server to the "authenticate" API described in {{Section 7.3 of ExpAuth}}.
The client then constructs an Authentication or Proxy-Authentication header
field with the scheme "ExportedAuthenticator" and a single authentication
parameter "ea" containing the resulting authenticator, encoded using base64url.

Where a client has previously generated an authenticator for a given
`certificate_request_context`, it MAY remember and reuse the resulting
authenticator in subsequent requests.

## Validation

When a server receives a request containing an Authorization or
Proxy-Authorization header field, it takes the following steps to determine the
client's identity:

- The `certificate_request_context` is extracted from the authenticator using
  the "get context" API described in {{Section 7.2 of ExpAuth}}.
  - If the context was generated by the server and is still valid:
      - If the context has not previously been authenticated to by the client,
        proceed with validating the exported authenticator.
      - If the context has previously been authenticated to by the client, the
        server checks that the provided authenticator matches that previously
        provided by the client. If so, the server reuses the result of the
        previous authentication.
  - Otherwise, this header field should be ignored and the request processed as
    if it contained no authentication information; this likely results in a
    401/407 response with a fresh challenge.
- The authenticator is passed to the "validate" API described in {{Section 7.4
  of ExpAuth}}.
  - If validation is successful, a client identity is returned. The response is
    generated as appropriate for this identity (i.e. 200, 403, etc.).
  - If validation fails or results in an empty identity, the request is
    processed as if it contained no authentication information; this likely
    results in a 401/407 response with a fresh challenge.

Because the selection of appropriate credentials might require human interaction
or access to remote cryptographic resources, servers SHOULD continue to accept
authenticators for a given context for some time after it stops using that
context in challenges. This period SHOULD be on the order of 1-2 minutes, but
MAY be extended if the client continues to make requests with an identical
authenticator.

# Security Considerations

This mechanism defines an alternate way to obtain client certificates other than
in the initial TLS handshake.  While the signature of exported authenticator
values is expected to be equally secure, it is important to recognize that a
vulnerability in this code path is at least equal to a vulnerability in the TLS
handshake.

## Impersonation

If the certificate request context is predictable or stable, an attacker with
brief access to the client's private key and connection state can pre-generate
an authenticator that will be valid later in the connection. In order to guard
against this, servers SHOULD NOT reuse the same context in challenges over a
period longer than 60 seconds and MAY reject authenticators from contexts
last used for a challenge or request more than 5 minutes ago.

## Denial of Service

If a server does not reuse authenticator request contexts across challenges, the
requirement to remember the contexts can be used to consume memory on the server
through repeated unauthenticated requests. Servers SHOULD reuse contexts to
limit memory consumption and aggressively drop old contexts which have not been
successfully used for authenticated requests.

Servers MAY implement context reuse by a consistent mechanism of constructing
the context ID, such as a truncated hash of a local connection identifier
unknown to the client and the current time. Using this mechanism, servers need
only remember contexts which have been used for successful authentication, but
would need to reconstruct multiple potential contexts when validating a client's
authenticator.

## Confusion about State

Servers MUST NOT consider previously authenticated client identities as
applying to all subsequent requests made by the client. Clients might choose to
present different credentials on different requests.

# IANA Considerations

This document, if approved, requests IANA to register the following entry in the
"HTTP Authentication Schemes" registry maintained at
<https://www.iana.org/assignments/http-authschemes>.

Authentication Scheme Name:
: ExportedAuthenticator

Reference:
: This document

Notes:
: None


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
