# ratsd-token

Go packages for encoding and decoding RATSD evidence tokens. The legacy JSON
token is provided by `github.com/veraison/ratsd-token`; the CBOR/COSE token is
provided by the separate Go module `github.com/veraison/ratsd-token/v2`.

Both modules require Go 1.26 or newer. See [the CDDL specification](docs/ratsd-token.cddl)
and [the v2 token example](docs/ratsd-token-example.diag) for their wire formats.

The root module also contains `github.com/veraison/ratsd-token/tokens` for
attester payloads shared by RATSD and its consumers. It provides `TSMReport`
and `GPUEvidence` with JSON and CBOR support as appropriate. Their formats are
specified in [TSM report CDDL](docs/tsm-report.cddl) and
[NVIDIA GPU evidence CDDL](docs/nvidia-gpu-evidence.cddl).

Consumers of `github.com/veraison/ratsd/tokens` should switch to
`github.com/veraison/ratsd-token/tokens`. Once all such imports are updated,
they can remove the `github.com/veraison/ratsd` module requirement and run
`go mod tidy`.

## Token generator

`gen-ratsd-token` packages one or more component evidence tokens into a signed
RATSD v2 CBOR/COSE token. Its source is in
[`v2/cmd/gen-ratsd-token`](v2/cmd/gen-ratsd-token).

Build it from this checkout:

```sh
cd v2
go build -o gen-ratsd-token ./cmd/gen-ratsd-token
cd ..
```

Each component is specified as three positional arguments: its collection key,
media type, and file path. For example, from the repository root:

```sh
./v2/gen-ratsd-token \
  --key v2/cmd/gen-ratsd-token/testdata/ec-p256.jwk \
  --nonce 0123456789abcdef \
  --oemid 1337 \
  --output ratsd-token.cbor \
  cca \
    'application/eat-collection; profile="http://arm.com/CCA-SSD/1.0.0"' \
    v2/cmd/gen-ratsd-token/testdata/cca-good.cbor \
  eat-da \
    'application/eat-ucs+json; eat_profile="tag:linaro.org,2025:device#1.0.0"' \
    v2/cmd/gen-ratsd-token/testdata/da-spdm-good.cbor
```

The signing key must be a private JWK. Without `--key`, the command reads
`key.jwk` in the current directory. Supported keys are EC P-256/P-384/P-521,
Ed25519, and RSA with a `PS256`, `PS384`, or `PS512` JWK algorithm.
The included key is a public test fixture and must not be used for real signing.

`--nonce` takes a hex-encoded value; omitting it generates a random 64-byte
nonce. The default output is `ratsd-token.cbor`. Use `--help` for the remaining
claim overrides and logging options.

After building, `./scripts/gen-sample-token` generates a token using the bundled
fixtures and writes it into the current directory.

The utility and sample data were moved from `veraison/gen-ratsd-token` at commit
`96f2df7d9b0b01772255ca651d0f842354dd37bb`. The utility now uses this repository's
v2 module directly.

## Testing

Run tests in each module:

```sh
go test ./...
cd v2 && go test ./...
```

The library was moved from `veraison/ratsd` at commit
`7ab53a031ba9a376a69b86397c5ed60954d1894d`. Consumers of the old module
paths should update imports to the paths above.
