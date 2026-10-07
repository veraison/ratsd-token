# ratsd-token

Go packages for encoding and decoding RATSD evidence tokens. The legacy JSON
token is provided by `github.com/veraison/ratsd-token`; the CBOR/COSE token is
provided by the separate Go module `github.com/veraison/ratsd-token/v2`.

Both modules require Go 1.26 or newer. See [the CDDL specification](docs/ratsd-token.cddl)
and [the v2 token example](docs/ratsd-token-example.diag) for their wire formats.

## Testing

Run tests in each module:

```sh
go test ./...
cd v2 && go test ./...
```

The library was moved from `veraison/ratsd` at commit
`7ab53a031ba9a376a69b86397c5ed60954d1894d`. Consumers of the old module
paths should update imports to the paths above.
