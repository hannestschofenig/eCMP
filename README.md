# eCMP

`eCMP` is a compact client-side implementation of the Certificate Management
Protocol (CMP) for constrained or embedded environments.

This codebase is a fresh implementation that uses Mbed TLS with a cleaner separation between:

- CMP protocol processing
- cryptographic backend integration
- message transport

At the moment, the implementation focuses on a minimal but working subset:

- Initial Registration (`ir`)
- Initialization Response (`ip`)
- `certConf`
- `pkiConf`
- CMP error message parsing
- PBM-protected and signature-protected response verification

The main target is interoperability with the Mock CA from the
`cmp-test-suite` repository.

The code was written against `Mbed TLS 3.6.4` and the current build and test
documentation assumes exactly that version.

## Scope

This implementation is intentionally small.

It does not aim to cover the full CMP feature set yet. The current goal is to
provide a maintainable baseline with clear module boundaries that can be
extended over time.

The protocol work is based on:

- RFC 9483
- RFC 9810

## Repository Layout

The most relevant files are:

- `include/ecmp/ecmp.h`
  Public API for the current IR flow.
- `include/ecmp/ecmp_error.h`
  Central error code definitions.
- `include/ecmp/ecmp_cmp_status.h`
  Symbolic CMP status, body type, and `failInfo` definitions.
- `src/ecmp_cmp.c`
  CMP message encoding, parsing, protection handling, and response checks.
- `src/ecmp_crypto_mbedtls.c`
  Mbed TLS based crypto provider implementation.
- `src/ecmp_transport_http.c`
  HTTP transport implementation.
- `src/ecmp_client.c`
  High-level IR orchestration and result handling.
- `program/main.c`
  Small command-line client for manual testing.

## Architecture

### 1. CMP Core

The CMP core is responsible for:

- building CMP messages
- parsing CMP responses
- checking protocol invariants
- validating PBM or signature-based protection
- tracking CMP transaction state across the IR exchange

This logic lives primarily in `src/ecmp_cmp.c`.

The CMP core should not need to know how keys are stored, how hashes and
signatures are computed internally, or how bytes are transported over the
network.

### 2. Crypto Provider

The crypto layer is abstracted through the provider interface declared in
`include/ecmp/ecmp_crypto.h`.

The current implementation uses Mbed TLS in:

- `src/ecmp_crypto_mbedtls.c`

This keeps the CMP logic decoupled from direct Mbed TLS usage as far as
possible. Replacing the crypto backend later should require significantly less
protocol refactoring than in the older implementation.

### 3. Transport Layer

The transport layer is abstracted through `include/ecmp/ecmp_transport.h`.

The current transport implementation is:

- HTTP in `src/ecmp_transport_http.c`

This design should make it straightforward to add other transports later, for
example:

- CoAP
- custom message bus transports
- test doubles for unit/integration testing

## Dependency on Mbed TLS

`eCMP` builds against `Mbed TLS 3.6.4` and is intended to vendor it as a Git
submodule.

Expected location:

- `external/mbedtls`

This keeps the repository self-contained and avoids depending on sources from a
separate neighboring project.

### Adding the Submodule

If you are setting up the repository for the first time:

```bash
git submodule add https://github.com/Mbed-TLS/mbedtls.git external/mbedtls
git submodule update --init --recursive
cd external/mbedtls
git checkout mbedtls-3.6.4
cd ../..
```

If the submodule entry already exists, you only need:

```bash
git submodule update --init --recursive
cd external/mbedtls
git checkout mbedtls-3.6.4
cd ../..
```

After that, commit the updated submodule pointer in the `eCMP` repository.

### Version Requirement

`eCMP` was implemented and exercised with `Mbed TLS 3.6.4`.

That matters for two reasons:

- the code was written against the `3.6.4` public API and behavior
- the current integration and manual test flow were verified with that version

Using a different Mbed TLS release may still work, but it is not what this
repository currently documents or tests against. If you change the Mbed TLS
version, treat that as an explicit compatibility exercise.

### CMake Integration

`CMakeLists.txt` expects the Mbed TLS source tree at `external/mbedtls` by
default and will stop with a clear error if it is missing.

You can override the path explicitly if needed:

```bash
cmake -S . -B build -DMBEDTLS_ROOT=/path/to/mbedtls
```

## Build

From the `eCMP` repository root:

```bash
git submodule update --init --recursive
cd external/mbedtls
git checkout mbedtls-3.6.4
cd ../..
cmake -S . -B build
cmake --build build -j4
```

If you want to start from a fresh clone:

```bash
git clone --recursive <repo-url>
cd eCMP
cd external/mbedtls
git checkout mbedtls-3.6.4
cd ../..
cmake -S . -B build
cmake --build build -j4
```

This builds:

- `libecmp.a`
- `build/ecmp_client`

## Static Analysis

`eCMP` can be checked with both the GCC static analyzer and `clang-tidy`.

### GCC Static Analyzer

For a lightweight first pass, run:

```bash
gcc -std=c99 -pedantic -Wall -Wextra -fanalyzer -fsyntax-only \
  -I./include \
  -I./src \
  -I./external/mbedtls/include \
  -DMBEDTLS_CONFIG_FILE=\"$(pwd)/external/mbedtls/include/mbedtls/mbedtls_config.h\" \
  src/ecmp_client.c src/ecmp_cmp.c src/ecmp_crypto_mbedtls.c \
  src/ecmp_transport_http.c program/main.c
```

This is useful for catching straightforward issues such as:

- missing cleanup on error paths
- obvious leak paths
- null dereferences
- simple misuse of uninitialized values

### clang-tidy

The repository contains a local `.clang-tidy` file that keeps the useful
`clang-analyzer-*` and `bugprone-*` checks enabled while filtering out the
known high-volume noise from Mbed TLS ASN.1 helper macros.

Run it from the `eCMP` repository root like this:

```bash
clang-tidy \
  src/ecmp_client.c \
  src/ecmp_cmp.c \
  src/ecmp_crypto_mbedtls.c \
  src/ecmp_transport_http.c \
  program/main.c \
  -header-filter='^.*/eCMP/(include|src|program)/.*' \
  --extra-arg=-std=c99 \
  --extra-arg=-I$(pwd)/include \
  --extra-arg=-I$(pwd)/src \
  --extra-arg=-I$(pwd)/external/mbedtls/include \
  --extra-arg=-DMBEDTLS_CONFIG_FILE=\"$(pwd)/external/mbedtls/include/mbedtls/mbedtls_config.h\" \
  --
```

If you are still working against an external Mbed TLS checkout instead of the
submodule layout, replace:

- `$(pwd)/external/mbedtls/include`

with the actual include directory of that checkout.

### Typical Session

From the `eCMP` repository root:

```bash
git submodule update --init --recursive
cd external/mbedtls
git checkout mbedtls-3.6.4
cd ../..
cmake -S . -B build
cmake --build build -j4
```

From the sibling `cmp-test-suite` checkout:

```bash
cd ../cmp-test-suite
python3 -m venv venv-cmp-tests
source venv-cmp-tests/bin/activate
make start-mock-ca
```

Back in `eCMP`:

```bash
cd ../eCMP
./build/ecmp_client -i \
  --sender "CN=ecmp-dev-$(date +%s)" \
  --subject "CN=ecmp-dev-$(date +%s)" \
  --kid "ecmp-dev-$(date +%s)" \
  --write-debug-meta
```

Useful artifacts to inspect after a run:

- `out/last_request.der`
- `out/last_response.der`
- `out/last_response.meta.txt`
- `out/new_cert.pem`
- `out/new_key.pem`

## Running the Mock CA

The intended test server is the Mock CA from `cmp-test-suite`.

This repository does not include the Mock CA. The expected development setup is
that `cmp-test-suite` is available next to `eCMP` in the same parent
directory.

Start it like this:

```bash
cd ../cmp-test-suite
python3 -m venv venv-cmp-tests
source venv-cmp-tests/bin/activate
make start-mock-ca
```

The default `eCMP` client settings expect:

- host: `127.0.0.1`
- port: `5000`
- path: `issuing`

## Running the Client

With the Mock CA running:

```bash
cd ../eCMP
./build/ecmp_client -i
```

The default IR configuration uses:

- sender: `CN=embeddedcmp-ir`
- recipient: `CN=recip`
- subject: `CN=embeddedcmp-ir`
- PBM secret: `SiemensIT`
- key identifier: `embeddedcmp-ir`
- EC curve: `secp256r1`

For repeated manual runs, it is usually better to provide a unique subject and
sender:

```bash
./build/ecmp_client -i \
  --sender "CN=ecmp-test-$(date +%s)" \
  --subject "CN=ecmp-test-$(date +%s)" \
  --kid "ecmp-test-$(date +%s)"
```

## Command Line Options

Current CLI usage:

```text
Usage: ./build/ecmp_client -i [--implicit-confirm] [--output DIR]
       [--host HOST] [--port PORT] [--path PATH]
       [--sender DN] [--recipient DN] [--subject DN]
       [--secret SECRET] [--kid KID] [--curve CURVE]
       [--write-debug-meta]
```

Important options:

- `-i`
  Run the Initial Registration flow.
- `--implicit-confirm`
  Request implicit confirmation.
- `--output DIR`
  Directory for generated output files.
- `--write-debug-meta`
  Write an additional text file with interpreted CMP response metadata.

## Output Files

After a successful run, the client writes artifacts into `eCMP/out` by default.

Typical files include:

- `last_request.der`
  DER-encoded last CMP request.
- `last_response.der`
  DER-encoded last CMP response.
- `last_response.meta.txt`
  Optional interpreted metadata for debugging.
- `new_cert.der`
  Enrolled certificate in DER form.
- `new_cert.pem`
  Enrolled certificate in PEM form.
- `new_key.pem`
  Generated private key in PEM form.
- `extra_certs.der`
  Additional CMP certificates in DER form.
- `extra_certs.pem`
  Additional CMP certificates in PEM form.

## Debug Metadata

If `--write-debug-meta` is enabled, the client writes
`out/last_response.meta.txt`.

This file is meant to make CMP interoperability debugging easier. It currently
includes fields such as:

- CMP body type
- protection algorithm
- sender and recipient
- sender key identifier
- transaction ID
- sender nonce
- recipient nonce
- CMP status
- CMP `failInfo`
- optional status text

Example:

```text
responseBodyType: ip (1)
protectionAlg: passwordBasedMac
protectionAlgOid: 2a864886f67d07420d
sender: CN=ecmp-meta-1773556913
recipient: CN=Mock CA
senderKID: 65636d702d6d6574612d31373733353536393133
transactionID: 0bbf7d6ce307ea3eef18d7b7f3b75263
senderNonce: 4c48090f80b7ef1045b7685dad91fa86
recipNonce: 7c533f471370f5388bad3bb247366d99
cmpStatus: accepted (0)
cmpFailInfo: none (0x00000000)
implicitConfirmGranted: false
```

## Error Handling

The code uses centralized symbolic error codes instead of scattered raw integer
values.

There are two different categories of errors:

### Local Client Errors

Defined in `include/ecmp/ecmp_error.h`, for example:

- `ECMP_ERR_ASN1`
- `ECMP_ERR_HTTP`
- `ECMP_ERR_NETWORK`
- `ECMP_ERR_PROTOCOL`
- `ECMP_ERR_CRYPTO_BACKEND`

These describe failures in the local implementation or runtime environment.

### CMP Server Rejections

Defined in `include/ecmp/ecmp_cmp_status.h`, for example:

- body types such as `ip`, `error`, `pkiConf`
- CMP status values such as `accepted` or `rejection`
- `failInfo` bits such as `badMessageCheck` or `signerNotTrusted`

This separation makes it easier to distinguish:

- "the client failed locally"
- from
- "the server rejected the CMP request"

## Current Status

The current implementation supports the minimal end-to-end IR flow against the
Mock CA and has been exercised with:

- PBM-protected responses
- signature-protected responses
- CMP error response parsing

It is still an early-stage codebase. Missing or incomplete areas include:

- broader CMP body coverage beyond the minimal registration path
- more extensive unit tests
- explicit trust-chain validation policy for all signed responses
- additional transports beyond HTTP
- cleanup of remaining workspace-coupled assumptions

## Limitations

At the moment, `eCMP` still assumes that the Mock CA lives in a separate
checkout of `cmp-test-suite`, typically next to this repository.

The Mbed TLS dependency is now expected to be local to this repository via
`external/mbedtls`, but the broader test environment is still workspace-based.

In addition, the current code and documentation are tied to `Mbed TLS 3.6.4`.

## Recommended Next Steps

The most useful improvements are likely:

1. add focused unit tests for ASN.1 parsing and CMP state transitions
2. make the Mbed TLS dependency configurable instead of hard-coded
3. add a second transport backend to validate the transport abstraction
4. extend support for additional CMP message types beyond IR
