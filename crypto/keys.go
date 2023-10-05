package crypto

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/kyber/v3/util/encoding"
	"os"
)

var curve = edwards25519.NewBlakeSHA256Ed25519()
var sha256 = curve.Hash()

type PrivateKey struct {
	kyber.Scalar
	kyber.Group
}
type PublicKey struct{}

func GetPrivateKey() ([]byte, error) {
	file := "./identity.txt"
	privKeyStr, err := os.ReadFile(file)
	if err != nil {
		panic(err)
	}
	return privKeyStr, nil
}

type IKeys interface {
	Private() kyber.Scalar
	Public() kyber.Point
	Group() kyber.Group
}

type Keys struct{}

func (k *Keys) Suite() suites.Suite {
	return suites.MustFind("edwards25519")
}

func (k *Keys) Private() kyber.Scalar {
	return curve.Scalar().Pick(curve.RandomStream())
}

func (k *Keys) Public() kyber.Point {
	return curve.Point().Mul(k.Private(), nil)
}

func (k *Keys) Group() kyber.Group {
	return curve
}

func (k *Keys) Hash(s string) kyber.Scalar {
	sha256.Reset()
	sha256.Write([]byte(s))

	return curve.Scalar().SetBytes(sha256.Sum(nil))
}

func NewKeys() *Keys {
	return &Keys{}
}

func (k *Keys) PrivateToString() (string, error) {
	hex, err := encoding.ScalarToStringHex(curve, k.Private())
	if err != nil {
		return "", err
	}
	return hex, nil
}

func (k *Keys) PublicToString() (string, error) {
	hex, err := encoding.PointToStringHex(curve, k.Public())
	return hex, err
}

func (k *Keys) StringToPriv(hex string) (kyber.Scalar, error) {
	str, err := encoding.StringHexToScalar(curve, hex)
	return str, err
}

func (k *Keys) StringToPub(hex string) (kyber.Point, error) {
	str, err := encoding.StringHexToPoint(curve, hex)
	return str, err
}

func (k *Keys) DerivePubKey(m string, s Signature) kyber.Point {

	return k.PublicKey(m, s)

}

func (k *Keys) PublicKey(m string, S Signature) kyber.Point {
	// Create a generator.
	g := curve.Point().Base()

	// e = Hash(m || r)
	e := k.Hash(m + S.r.String())

	// y = (r - s * G) * (1 / e)
	y := curve.Point().Sub(S.r, curve.Point().Mul(S.s, g))
	y = curve.Point().Mul(curve.Scalar().Div(curve.Scalar().One(), e), y)

	return y
}

type Signature struct {
	r kyber.Point
	s kyber.Scalar
}

func (k *Keys) Sign(m string, x kyber.Scalar) Signature {
	// Get the base of the curve.
	g := curve.Point().Base()

	// Pick a random k from allowed set.
	k1 := curve.Scalar().Pick(curve.RandomStream())

	// r = k * G (a.k.a the same operation as r = g^k)
	r := curve.Point().Mul(k1, g)

	// Hash(m || r)
	e := k.Hash(m + r.String())

	// s = k - e * x
	s := curve.Scalar().Sub(k1, curve.Scalar().Mul(e, x))

	return Signature{r: r, s: s}
}

func (k *Keys) Verify(m string, S Signature, y kyber.Point) bool {
	// Create a generator.
	g := curve.Point().Base()

	// e = Hash(m || r)
	e := k.Hash(m + S.r.String())

	// Attempt to reconstruct 's * G' with a provided signature; s * G = r - e * y
	sGv := curve.Point().Sub(S.r, curve.Point().Mul(e, y))

	// Construct the actual 's * G'
	sG := curve.Point().Mul(S.s, g)

	// Equality check; ensure signature and public key outputs to s * G.
	return sG.Equal(sGv)
}
