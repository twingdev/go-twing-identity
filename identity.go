package go_twing_identity

import (
	"github.com/twingdev/go-twing-identity/crypto"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/group/edwards25519"
)

type Identity struct {
	*crypto.Keys
}

func NewIdentity() *Identity {
	return &Identity{}
}

func (i *Identity) GetEd25519Private() kyber.Scalar {

	ed := edwards25519.SuiteEd25519{}
	return ed.NewKey(ed.RandomStream())

}
