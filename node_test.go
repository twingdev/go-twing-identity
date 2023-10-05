package go_twing_identity

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewNode(t *testing.T) {
	n, err := NewNode()
	require.NoError(t, err, n)
}
