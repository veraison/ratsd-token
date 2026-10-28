package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/veraison/cmw"
	"github.com/veraison/go-cose"
	token "github.com/veraison/ratsd-token/v2"
)

func executeCommand(args ...string) error {
	command := NewRootCommand()
	command.SetArgs(args)
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	return command.Execute()
}

func readVerifiedEvidence(test *testing.T, path, keyPath string) *token.Evidence {
	test.Helper()

	encoded, err := os.ReadFile(path)
	require.NoError(test, err)
	var evidence token.Evidence
	require.NoError(test, evidence.FromCBOR(encoded))

	keyBytes, err := os.ReadFile(keyPath)
	require.NoError(test, err)
	algorithm, key, err := getAlgAndKeyFromJWK(keyBytes)
	require.NoError(test, err)
	verifier, err := cose.NewVerifier(algorithm, key.Public())
	require.NoError(test, err)
	require.NoError(test, evidence.Verify(verifier))
	return &evidence
}

func TestGenerateSignedToken(test *testing.T) {
	components := []struct {
		key       string
		mediaType string
		path      string
	}{
		{"cca", `application/eat-collection; profile="http://arm.com/CCA-SSD/1.0.0"`, "testdata/cca-good.cbor"},
		{"eat-da", `application/eat-ucs+json; eat_profile="tag:linaro.org,2025:device#1.0.0"`, "testdata/da-spdm-good.cbor"},
	}
	for _, componentCount := range []int{1, 2} {
		test.Run(components[componentCount-1].key, func(test *testing.T) {
			outputPath := filepath.Join(test.TempDir(), "token.cbor")
			args := []string{
				"--key", "testdata/ec-p256.jwk", "--output", outputPath,
				"--nonce", "0123456789abcdef", "--oemid", "1337",
				"--swname", "test-attester", "--swversion", "1.2.3",
			}
			for _, component := range components[:componentCount] {
				args = append(args, component.key, component.mediaType, component.path)
			}
			require.NoError(test, executeCommand(args...))

			evidence := readVerifiedEvidence(test, outputPath, "testdata/ec-p256.jwk")
			nonce, err := hex.DecodeString("0123456789abcdef")
			require.NoError(test, err)
			assert.Equal(test, nonce, evidence.Claims.GetEatNonce())
			assert.Equal(test, token.Profile, evidence.Claims.GetEatProfile())
			assert.Equal(test, int64(1337), evidence.Claims.GetOEMID())
			assert.Equal(test, "test-attester", evidence.Claims.GetSWName())
			assert.Equal(test, "1.2.3", evidence.Claims.GetSWVersion())
			for _, component := range components[:componentCount] {
				record, err := evidence.Collection.GetCollectionItem(component.key)
				require.NoError(test, err)
				mediaType, err := record.GetMonadType()
				require.NoError(test, err)
				assert.Equal(test, component.mediaType, mediaType)
				data, err := record.GetMonadValue()
				require.NoError(test, err)
				expected, err := os.ReadFile(component.path)
				require.NoError(test, err)
				assert.Equal(test, expected, data)
				indicator, err := record.GetMonadIndicator()
				require.NoError(test, err)
				assert.Equal(test, cmw.Indicator(cmw.Evidence), indicator)
			}
		})
	}
}

func TestGenerateTokenDefaults(test *testing.T) {
	keyBytes, err := os.ReadFile("testdata/ec-p256.jwk")
	require.NoError(test, err)
	componentBytes, err := os.ReadFile("testdata/cca-good.cbor")
	require.NoError(test, err)
	test.Chdir(test.TempDir())
	require.NoError(test, os.WriteFile("key.jwk", keyBytes, 0600))
	require.NoError(test, os.WriteFile("component.cbor", componentBytes, 0600))

	var previousNonce []byte
	for range 2 {
		require.NoError(test, executeCommand("cca", "application/octet-stream", "component.cbor"))
		evidence := readVerifiedEvidence(test, "ratsd-token.cbor", "key.jwk")
		assert.Len(test, evidence.Claims.GetEatNonce(), 64)
		assert.NotEqual(test, previousNonce, evidence.Claims.GetEatNonce())
		assert.Equal(test, token.DefaultLeadAttesterOEMID, evidence.Claims.GetOEMID())
		assert.Equal(test, token.DefaultLeadAttesterSWName, evidence.Claims.GetSWName())
		assert.Equal(test, token.DefaultLeadAttesterSWVersion, evidence.Claims.GetSWVersion())
		previousNonce = evidence.Claims.GetEatNonce()
	}
}

func TestGenerateTokenRejectsInvalidInput(test *testing.T) {
	component := []string{"cca", "application/octet-stream", "testdata/cca-good.cbor"}
	tests := []struct {
		name string
		args []string
	}{
		{"no components", nil},
		{"incomplete component", component[:2]},
		{"short nonce", append([]string{"--nonce", "01"}, component...)},
		{"invalid nonce encoding", append([]string{"--nonce", "not-hex"}, component...)},
		{"invalid OEM ID", append([]string{"--oemid", "0"}, component...)},
		{"empty software name", append([]string{"--swname", ""}, component...)},
		{"missing component file", []string{"cca", "application/octet-stream", "testdata/missing.cbor"}},
		{"missing key", append([]string{"--key", "testdata/missing.jwk"}, component...)},
		{"invalid key", append([]string{"--key", "testdata/cca-good.cbor"}, component...)},
		{"invalid media type", []string{"cca", "", "testdata/cca-good.cbor"}},
		{"reserved key", []string{"__ratsd", "application/octet-stream", "testdata/cca-good.cbor"}},
		{"invalid final component", append(append([]string{}, component...), "bad", "", "testdata/cca-good.cbor")},
	}
	for _, testCase := range tests {
		test.Run(testCase.name, func(test *testing.T) {
			outputPath := filepath.Join(test.TempDir(), "token.cbor")
			args := append([]string{"--key", "testdata/ec-p256.jwk", "--output", outputPath}, testCase.args...)
			require.Error(test, executeCommand(args...))
			_, err := os.Stat(outputPath)
			assert.ErrorIs(test, err, os.ErrNotExist)
		})
	}
}

func TestSignerKeyTypes(test *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(test, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(test, err)
	tests := []struct {
		name      string
		key       crypto.Signer
		curve     elliptic.Curve
		algorithm cose.Algorithm
	}{
		{"EdDSA", edKey, nil, cose.AlgorithmEdDSA},
		{"PS256", rsaKey, nil, cose.AlgorithmPS256},
		{"PS384", rsaKey, nil, cose.AlgorithmPS384},
		{"PS512", rsaKey, nil, cose.AlgorithmPS512},
		{"ES256", nil, elliptic.P256(), cose.AlgorithmES256},
		{"ES384", nil, elliptic.P384(), cose.AlgorithmES384},
		{"ES512", nil, elliptic.P521(), cose.AlgorithmES512},
	}
	for _, testCase := range tests {
		test.Run(testCase.name, func(test *testing.T) {
			if testCase.curve != nil {
				key, err := ecdsa.GenerateKey(testCase.curve, rand.Reader)
				require.NoError(test, err)
				testCase.key = key
			}
			jwkKey, err := jwk.FromRaw(testCase.key)
			require.NoError(test, err)
			if _, isRSA := testCase.key.(*rsa.PrivateKey); isRSA {
				require.NoError(test, jwkKey.Set(jwk.AlgorithmKey, testCase.name))
			}
			keyBytes, err := json.Marshal(jwkKey)
			require.NoError(test, err)
			signer, err := newSignerFromJWK(keyBytes)
			require.NoError(test, err)
			assert.Equal(test, testCase.algorithm, signer.Algorithm())
			signature, err := signer.Sign(rand.Reader, []byte("ratsd-token generator test"))
			require.NoError(test, err)
			verifier, err := cose.NewVerifier(testCase.algorithm, testCase.key.Public())
			require.NoError(test, err)
			assert.NoError(test, verifier.Verify([]byte("ratsd-token generator test"), signature))
		})
	}
}
