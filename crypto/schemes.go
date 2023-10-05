package crypto

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	dkg "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	"hash"
)

type Scheme struct {
	Name          string
	SigGroup      kyber.Group
	KeyGroup      kyber.Group
	DKGAuthScheme *DKGNode
	AuthScheme    pairing.Suite
	IdentityHash  func() hash.Hash
	Digest        func(interface{}) []byte
}

type DKGNode struct {
	dkg         *dkg.DistKeyGenerator
	pubKey      kyber.Point
	privKey     kyber.Scalar
	deals       []*dkg.Deal
	resps       []*dkg.Response
	secretShare *share.PriShare
}

func newPairing() *pairing.SuiteBn256 {

	return pairing.NewSuiteBn256()
}
