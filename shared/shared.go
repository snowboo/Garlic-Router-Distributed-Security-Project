package shared

import (
	"crypto/rsa"
	"sync"
)

// Message Package
type Package struct {
	TunnelID      int
	EncryptedData []byte
}

type InfoPackage struct {
	GatewayInfo   TunnelGatewayInfo
	EncryptedData []byte
}

const (
	/* Tunnel Roles*/
	GATEWAY     = 0
	PARTICIPANT = 1
	ENDPOINT    = 2
	TO_DELETE   = -1
	/* Tunnel ID */
	FLOODING            = -2 // non-encrypted, TunnelInfo, used for gateway info flooding
	TUNNEL_MAP_FLOODING = -3
	REQUEST_GATEWAY_MAP = -4
	SEND_GATEWAY_MAP    = -5
)

type TunnelInfo struct {
	TunnelID          int
	TunnelRole        int // gateway 0, participant 1, endpoint 2, deleteThisTunnel -1
	NextHopIp         string
	TunnelKey         *[32]byte
	TunnelEndpointKey *[32]byte
}

type TunnelGatewayInfo struct {
	TunnelID        int
	TunnelGatewayIP string
	TunnelKey       *[32]byte
}

type TunnelNodes struct {
	IsInbound         bool
	TunnelKey         *[32]byte
	TunnelEndpointKey *[32]byte
	NodesRouterKeys   []*rsa.PublicKey
	NodesAddresses    []string
}

type RegisterNode struct {
	NodeIp       string
	RouterPubKey *rsa.PublicKey
}

type UpdateTunnelInfoMessage struct {
	NodeID      int
	GatewayInfo TunnelGatewayInfo
}

type Message struct {
	AESKey             *[32]byte
	PseudonymPublicKey string
	MessageString      string
	NodeID             int
	NeedsReply         bool
}

type MessageReply struct {
	sync.RWMutex
	WaitingForReply int
}

type MessageRPC struct {
	NodeID       []int
	PseudoPubKey []string
	Message      []string
	NeedsReply   bool
}
