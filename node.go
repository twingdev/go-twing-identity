package go_twing_identity

import (
	"fmt"
	"github.com/libp2p/go-libp2p"
	lcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"golang.org/x/crypto/ed25519"
	"log"
)

func NewNode() (host.Host, error) {
	id := NewIdentity()
	privBytes, _ := id.Private().MarshalBinary()
	edk := ed25519.NewKeyFromSeed(privBytes)

	log.Println(edk)
	key, err := lcrypto.UnmarshalEd25519PrivateKey(edk)
	if err != nil {
		return nil, err
	}
	opts := []libp2p.Option{
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/127.0.0.1/tcp/%d", 55435)),
		libp2p.Identity(key),
		libp2p.DisableRelay(),
	}

	return libp2p.New(opts...)

}
