package dnsx

// DNS over QUIC Probe Support
type DOQClient struct {
    Server string
}

func NewDOQClient(server string) *DOQClient {
    return &DOQClient{Server: server}
}
