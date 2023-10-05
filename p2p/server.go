// Copyright 2014 The Spectrum Authors
// This file is part of the Spectrum library.
//
// The Spectrum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Spectrum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Spectrum library. If not, see <http://www.gnu.org/licenses/>.

// Package p2p implements the Ethereum p2p network protocols.
package p2p

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/cc14514/go-alibp2p"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SmartMeshFoundation/Spectrum/common"
	"github.com/SmartMeshFoundation/Spectrum/event"
	"github.com/SmartMeshFoundation/Spectrum/log"
	"github.com/SmartMeshFoundation/Spectrum/p2p/discover"
	"github.com/SmartMeshFoundation/Spectrum/p2p/discv5"
	"github.com/SmartMeshFoundation/Spectrum/p2p/nat"
	"github.com/SmartMeshFoundation/Spectrum/p2p/netutil"
	"github.com/cc14514/go-cookiekit/collections/set"
)

const (
	defaultDialTimeout      = 15 * time.Second
	refreshPeersInterval    = 30 * time.Second
	staticPeerCheckInterval = 15 * time.Second

	// Maximum number of concurrently handshaking inbound connections.
	maxAcceptConns = 50

	// Maximum number of concurrently dialing outbound connections.
	maxActiveDialTasks = 16

	// Maximum time allowed for reading a complete message.
	// This is effectively the amount of time a connection can be idle.
	frameReadTimeout = 30 * time.Second

	// Maximum amount of time allowed for writing a complete message.
	frameWriteTimeout = 20 * time.Second
)

var (
	errServerStopped = errors.New("server stopped")
	errServerTimeout = errors.New("server timeout")
)

// Config holds Server options.
type Config struct {
	// This field must be set to a valid secp256k1 private key.
	PrivateKey *ecdsa.PrivateKey `toml:"-"`

	// MaxPeers is the maximum number of peers that can be
	// connected. It must be greater than zero.
	MaxPeers int

	// MaxPendingPeers is the maximum number of peers that can be pending in the
	// handshake phase, counted separately for inbound and outbound connections.
	// Zero defaults to preset values.
	MaxPendingPeers int `toml:",omitempty"`

	// NoDiscovery can be used to disable the peer discovery mechanism.
	// Disabling is useful for protocol debugging (manual topology).
	NoDiscovery bool

	// DiscoveryV5 specifies whether the the new topic-discovery based V5 discovery
	// protocol should be started or not.
	DiscoveryV5 bool `toml:",omitempty"`

	// Listener address for the V5 discovery protocol UDP traffic.
	DiscoveryV5Addr string `toml:",omitempty"`

	// Name sets the node name of this server.
	// Use common.MakeName to create a name that follows existing conventions.
	Name string `toml:"-"`

	// BootstrapNodes are used to establish connectivity
	// with the rest of the network.
	Alibp2pBootstrapNodes []string // add by liangc for alibp2p
	BootstrapNodes        []*discover.Node

	// BootstrapNodesV5 are used to establish connectivity
	// with the rest of the network using the V5 discovery
	// protocol.
	BootstrapNodesV5 []*discv5.Node `toml:",omitempty"`

	// Static nodes are used as pre-configured connections which are always
	// maintained and re-connected on disconnects.
	StaticNodes []*discover.Node

	// Trusted nodes are used as pre-configured connections which are always
	// allowed to connect, even above the peer limit.
	TrustedNodes []*discover.Node

	// Connectivity can be restricted to certain IP networks.
	// If this option is set to a non-nil value, only hosts which match one of the
	// IP networks contained in the list are considered.
	NetRestrict *netutil.Netlist `toml:",omitempty"`

	// NodeDatabase is the path to the database containing the previously seen
	// live nodes in the network.
	NodeDatabase string `toml:",omitempty"`

	// Protocols should contain the protocols supported
	// by the server. Matching protocols are launched for
	// each peer.
	Protocols []Protocol `toml:"-"`

	// If ListenAddr is set to a non-nil address, the server
	// will listen for incoming connections.
	//
	// If the port is zero, the operating system will pick a port. The
	// ListenAddr field will be updated with the actual address when
	// the server is started.
	ListenAddr string

	// If set to a non-nil value, the given NAT port mapper
	// is used to make the listening port available to the
	// Internet.
	NAT nat.Interface `toml:",omitempty"`

	// If Dialer is set to a non-nil value, the given Dialer
	// is used to dial outbound peer connections.
	Dialer NodeDialer `toml:"-"`

	// If NoDial is true, the server will not dial any peers.
	NoDial bool `toml:",omitempty"`

	// If EnableMsgEvents is set then the server will emit PeerEvents
	// whenever a message is sent to or received from a peer
	EnableMsgEvents bool

	// Logger is a custom logger to use with the p2p.Server.
	Logger log.Logger

	// 200630 add by liangc
	GenesisHash common.Hash

	// 201221 add by liangc
	NetmuxPort uint64

	NetworkId uint64
}

// Server manages all peer connections.
type Server struct {
	// Config fields may not be modified while the server is running.
	Config

	// Hooks for testing. These are useful because we can inhibit
	// the whole protocol stack.
	newTransport func(net.Conn) transport
	newPeerHook  func(*Peer)

	lock    sync.Mutex // protects running
	running bool

	ntab         discoverTable
	listener     net.Listener
	ourHandshake *protoHandshake
	lastLookup   time.Time
	DiscV5       *discv5.Network

	// These are for Peers, PeerCount (and nothing else).
	peerOp     chan peerOpFunc
	peerOpDone chan struct{}

	quit          chan struct{}
	addstatic     chan *discover.Node
	removestatic  chan *discover.Node
	posthandshake chan *conn
	addpeer       chan *conn
	delpeer       chan peerDrop
	loopWG        sync.WaitGroup // loop, listenLoop
	peerFeed      event.Feed
	log           log.Logger

	alibp2pService *Alibp2p // add by liangc
}

type peerOpFunc func(map[discover.NodeID]*Peer)

type peerDrop struct {
	*Peer
	err       error
	requested bool // true if signaled by the peer
}

type connFlag int
type ConnFlag connFlag

const (
	dynDialedConn connFlag = 1 << iota
	staticDialedConn
	inboundConn
	trustedConn

	ignoreConn // add by liangc : 握手时如果得到这个标记则表明 忽略握手保持连接
)

// conn wraps a network connection with information gathered
// during the two handshakes.
type conn struct {
	fd net.Conn
	transport
	flags connFlag
	cont  chan error      // The run loop uses cont to signal errors to SetupConn.
	id    discover.NodeID // valid after the encryption handshake
	caps  []Cap           // valid after the protocol handshake
	name  string          // valid after the protocol handshake

	session        string   // add by liangc
	protocols      *set.Set // 200813 : add by liangc : 用来判断 peer 是否支持某个版本的协议
	alibp2pservice *Alibp2p // add by liangc
}

type transport interface {
	// The two handshakes.
	doEncHandshake(prv *ecdsa.PrivateKey, dialDest *discover.Node) (discover.NodeID, error)
	doProtoHandshake(our *protoHandshake) (*protoHandshake, error)
	// The MsgReadWriter can only be used after the encryption
	// handshake has completed. The code uses conn.id to track this
	// by setting it to a non-nil value after the encryption handshake.
	MsgReadWriter
	// transports must provide Close because we use MsgPipe in some of
	// the tests. Closing the actual network connection doesn't do
	// anything in those tests because NsgPipe doesn't use it.
	close(err error)
}

func (c *conn) String() string {
	s := c.flags.String()
	if (c.id != discover.NodeID{}) {
		s += " " + c.id.String()
	}
	s += " " + c.fd.RemoteAddr().String()
	return s
}

func (f connFlag) String() string {
	s := ""
	if f&trustedConn != 0 {
		s += "-trusted"
	}
	if f&dynDialedConn != 0 {
		s += "-dyndial"
	}
	if f&staticDialedConn != 0 {
		s += "-staticdial"
	}
	if f&inboundConn != 0 {
		s += "-inbound"
	}
	if s != "" {
		s = s[1:]
	}
	return s
}

func (c *conn) is(f connFlag) bool {
	return c.flags&f != 0
}

// Peers returns all connected peers.
func (srv *Server) Peers() []*Peer {
	var ps []*Peer
	select {
	// Note: We'd love to put this function into a variable but
	// that seems to cause a weird compiler error in some
	// environments.
	case srv.peerOp <- func(peers map[discover.NodeID]*Peer) {
		for _, p := range peers {
			ps = append(ps, p)
		}
	}:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return ps
}

// PeerCount returns the number of connected peers.
func (srv *Server) PeerCount() int {
	var count int
	select {
	case srv.peerOp <- func(ps map[discover.NodeID]*Peer) { count = len(ps) }:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return count
}

// AddPeer connects to the given node and maintains the connection until the
// server is shut down. If the connection fails for any reason, the server will
// attempt to reconnect the peer.
func (srv *Server) AddPeer(node *discover.Node) {
	select {
	case srv.addstatic <- node:
	case <-srv.quit:
	}
}

// RemovePeer disconnects from the given node
func (srv *Server) RemovePeer(node *discover.Node) {
	select {
	case srv.removestatic <- node:
	case <-srv.quit:
	}
}

// SubscribePeers subscribes the given channel to peer events
func (srv *Server) SubscribeEvents(ch chan *PeerEvent) event.Subscription {
	return srv.peerFeed.Subscribe(ch)
}

// Self returns the local node's endpoint information.
func (srv *Server) Self() *discover.Node {
	srv.lock.Lock()
	defer srv.lock.Unlock()

	if !srv.running {
		return &discover.Node{IP: net.ParseIP("0.0.0.0")}
	}
	return srv.makeSelf(srv.listener, srv.ntab)
}

func (srv *Server) makeSelf(listener net.Listener, ntab discoverTable) *discover.Node {
	// If the server's not running, return an empty node.
	// If the node is running but discovery is off, manually assemble the node infos.
	if ntab == nil {
		// Inbound connections disabled, use zero address.
		if listener == nil {
			return &discover.Node{IP: net.ParseIP("0.0.0.0"), ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}
		}
		// Otherwise inject the listener address too
		addr := listener.Addr().(*net.TCPAddr)
		return &discover.Node{
			ID:  discover.PubkeyID(&srv.PrivateKey.PublicKey),
			IP:  addr.IP,
			TCP: uint16(addr.Port),
		}
	}
	// Otherwise return the discovery node.
	return ntab.Self()
}

// Stop terminates the server and all active peer connections.
// It blocks until all active connections have been closed.
func (srv *Server) Stop() {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if !srv.running {
		return
	}
	srv.running = false
	if srv.listener != nil {
		// this unblocks listener Accept
		srv.listener.Close()
	}
	close(srv.quit)
	srv.loopWG.Wait()
}

// Start starts running the server.
// Servers can not be re-used after stopping.
func (srv *Server) Start() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true
	srv.log = srv.Config.Logger
	if srv.log == nil {
		srv.log = log.New()
	}
	srv.log.Info("Starting P2P networking")

	// static fields
	if srv.PrivateKey == nil {
		return fmt.Errorf("Server.PrivateKey must be set to a non-nil key")
	}
	if srv.newTransport == nil {
		srv.newTransport = newRLPX
	}
	if srv.Dialer == nil {
		srv.Dialer = TCPDialer{&net.Dialer{Timeout: defaultDialTimeout}}
	}
	srv.quit = make(chan struct{})
	srv.addpeer = make(chan *conn)
	srv.delpeer = make(chan peerDrop)
	srv.posthandshake = make(chan *conn)
	srv.addstatic = make(chan *discover.Node)
	srv.removestatic = make(chan *discover.Node)
	srv.peerOp = make(chan peerOpFunc)
	srv.peerOpDone = make(chan struct{})
	// add by liangc : libp2p transport
	srv.newTransport = newAlibp2pTransport

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		<-srv.quit
		cancel()
	}()

	p2pport, err := strconv.Atoi(strings.Split(srv.Config.ListenAddr, ":")[1])
	if err != nil {
		p2pport = 0
	}

	var muxPort uint64 = 5978
	// add by liangc : 201221
	if srv.Config.NetmuxPort > 0 {
		muxPort = srv.Config.NetmuxPort
	}

	// add by liangc : 如果 networkid 不传，默认用 genesishash 作为 nid
	var nid *big.Int
	if srv.Config.NetworkId <= 0 {
		nid = new(big.Int).SetBytes(srv.Config.GenesisHash.Bytes())
	} else {
		nid = big.NewInt(int64(srv.Config.NetworkId))
	}

	srv.alibp2pService = NewAlibp2p(
		ctx,
		p2pport,
		int(muxPort),
		srv.Config.MaxPeers,
		nid, srv, nil, nil,
		func(pubkey *ecdsa.PublicKey, msgType uint16, size uint32) error {
			// TODO
			return nil
		})
	srv.alibp2pService.Start()

	dynPeers := (srv.MaxPeers + 1) / 2
	if srv.NoDiscovery {
		dynPeers = 0
	}
	dialer := newDialState(srv.StaticNodes, srv.BootstrapNodes, srv.ntab, dynPeers, srv.NetRestrict)

	// handshake
	srv.ourHandshake = &protoHandshake{Version: baseProtocolVersion, Name: srv.Name, ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}

	srv.loopWG.Add(1)
	go srv.run(dialer)
	srv.running = true
	return nil
}

func (srv *Server) startListening() error {
	// Launch the TCP listener.
	listener, err := net.Listen("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	laddr := listener.Addr().(*net.TCPAddr)
	srv.ListenAddr = laddr.String()
	srv.listener = listener
	srv.loopWG.Add(1)
	go srv.listenLoop()
	// Map the TCP listening port if NAT is configured.
	if !laddr.IP.IsLoopback() && srv.NAT != nil {
		srv.loopWG.Add(1)
		go func() {
			nat.Map(srv.NAT, srv.quit, "tcp", laddr.Port, laddr.Port, "ethereum p2p")
			srv.loopWG.Done()
		}()
	}
	return nil
}

type dialer interface {
	newTasks(running int, peers map[discover.NodeID]*Peer, now time.Time) []task
	taskDone(task, time.Time)
	addStatic(*discover.Node)
	removeStatic(*discover.Node)
}

func (srv *Server) run(dialstate dialer) {
	defer srv.loopWG.Done()
	var (
		peers   = make(map[discover.NodeID]map[string]*Peer)
		trusted = make(map[discover.NodeID]bool, len(srv.TrustedNodes))
		// taskdone     = make(chan task, maxActiveDialTasks)
		runningTasks []task
		// queuedTasks  []task // tasks that can't run yet

		peersLock    = new(sync.Mutex)
		inboundCount = 0
	)

running:
	for {
		select {
		case <-srv.quit:
			// The server was stopped. Run the cleanup logic.
			break running
		case <-srv.addstatic:
			// pass
		case op := <-srv.peerOp:
			// This channel is used by Peers and PeerCount.
			rpeers := make(map[discover.NodeID]*Peer)

			for pid, pmap := range peers {
				for _, p := range pmap {
					rpeers[pid] = p
					break
				}
			}
			op(rpeers)
			srv.peerOpDone <- struct{}{}

		case c := <-srv.posthandshake:
			// A connection has passed the encryption handshake so
			// the remote identity is known (but hasn't been verified yet).
			if trusted[c.id] {
				// Ensure that the trusted flag is set before checking against MaxPeers.
				c.flags |= trustedConn
			}
			// TODO: track in-progress inbound node IDs (pre-Peer) to avoid dialing them.
			select {
			case c.cont <- srv.encHandshakeChecks(peers, inboundCount, c):
			case <-srv.quit:
				break running
			}
		case c := <-srv.addpeer:
			// At this point the connection is past the protocol handshake.
			// Its capabilities are known and the remote identity is verified.
			err := srv.protoHandshakeChecks(peers, inboundCount, c)
			if err == nil {
				// The handshakes are done and it passed all checks.
				p := newPeer(c, srv.Protocols)
				// If message events are enabled, pass the peerFeed
				// to the peer
				if srv.EnableMsgEvents {
					p.events = &srv.peerFeed
				}
				name := truncateName(c.name)
				srv.log.Debug("Adding p2p peer", "name", name, "peers", len(peers)+1)
				//srv.log.Debug("Adding p2p peer", "name", name, "addr", c.fd.RemoteAddr(), "peers", len(peers)+1)

				addpeerFn := func() {
					peersLock.Lock()
					defer peersLock.Unlock()
					pmap, ok := peers[c.id]
					if !ok {
						pmap = make(map[string]*Peer)
					}
					pmap[c.session] = p
					peers[c.id] = pmap
					//pubkey, _ := c.id.Pubkey()
					//id, _ := alibp2p.ECDSAPubEncode(pubkey)
					if p.Inbound() {
						inboundCount++
					}
				}
				addpeerEventCh := make(chan *AddpeerHandshakeEvent)
				addpeerEventSub := SubscribeAddpeerHandshakeEvent(addpeerEventCh)
				go srv.runPeer(p)
				go func() {
					defer func() {
						addpeerEventSub.Unsubscribe()
					}()
					log.Debug("-> addpeer-handshake-start", "id", c.name, "session", c.session)
					for e := range addpeerEventCh {
						if !bytes.Equal(e.Id, p.ID().Bytes()) {
							continue
						}
						if e.Err != nil {
							log.Debug("-> addpeer-handshake-fail", "id", c.name, "session", c.session, "err", e.Err)
							return
						}
						addpeerFn()
						log.Debug("-> addpeer-handshake-success", "id", c.name, "session", c.session, "pmap", len(peers[c.id]))
						return
					}
				}()
			}
			// The dialer logic relies on the assumption that
			// dial tasks complete after the peer has been added or
			// discarded. Unblock the task last.
			select {
			case c.cont <- err:
			case <-srv.quit:
				break running
			}
		case pd := <-srv.delpeer:
			func() {
				peersLock.Lock()
				defer peersLock.Unlock()
				// TODO 清理 session
				pmap, ok := peers[pd.ID()]
				pubkey, _ := pd.ID().Pubkey()
				id, _ := alibp2p.ECDSAPubEncode(pubkey)
				//dellogAdd(id, pd.rw.session)
				if pd.err.Error() == "unlink" {
					delete(peers, pd.ID())
				} else if ok {
					delete(pmap, pd.rw.session)
					log.Debug("<- delpeer : pmap-clean", "id", id, "session", pd.rw.session, "pmap", pmap)
					if len(pmap) == 0 {
						delete(peers, pd.ID())
						log.Debug("<- delpeer : pmap-0", "id", id)
					} else {
						peers[pd.ID()] = pmap
						log.Debug("<- delpeer : pmap-n", "id", id, "pmap", pmap)
					}
				}
				log.Debug("<- delpeer", "err", pd.err, "id", id, "session", pd.rw.session, "pmap", pmap)
				if pd.Inbound() {
					inboundCount--
				}
			}()
		}
	}

	srv.log.Trace("P2P networking is spinning down")

	// Terminate discovery. If there is a running lookup it will terminate soon.
	if srv.ntab != nil {
		srv.ntab.Close()
	}
	if srv.DiscV5 != nil {
		srv.DiscV5.Close()
	}
	// Disconnect all peers.
	for _, pmap := range peers {
		for s, p := range pmap {
			p.Disconnect(DiscQuitting)
			log.Debug("DiscQuitting", "id", s, "session", p.rw.session)
		}
	}
	// Wait for peers to shut down. Pending connections and tasks are
	// not handled here and will terminate soon-ish because srv.quit
	// is closed.
	for len(peers) > 0 {
		select {
		case p := <-srv.delpeer:
			log.Trace("<-delpeer (spindown)", "remainingTasks", len(runningTasks))
			delete(peers, p.ID())
		case <-srv.quit:
			return
		}

	}
}

func (srv *Server) protoHandshakeChecks(peers map[discover.NodeID]map[string]*Peer, inboundCount int, c *conn) error {
	// Drop connections with no matching protocols.
	if len(srv.Protocols) > 0 && countMatchingProtocols(srv.Protocols, c.caps) == 0 {
		return DiscUselessPeer
	}
	// Repeat the encryption handshake checks because the
	// peer set might have changed between the handshakes.
	return srv.encHandshakeChecks(peers, inboundCount, c)
}

func (srv *Server) encHandshakeChecks(peers map[discover.NodeID]map[string]*Peer, inboundCount int, c *conn) error {
	// XXX : modify by liangc , the verify process has moved to alibp2p
	// XXX : modify by liangc , the verify process has moved to alibp2p
	// XXX : modify by liangc , the verify process has moved to alibp2p
	return nil
}

type tempError interface {
	Temporary() bool
}

// listenLoop runs in its own goroutine and accepts
// inbound connections.
func (srv *Server) listenLoop() {
	defer srv.loopWG.Done()
	srv.log.Info("RLPx listener up", "self", srv.makeSelf(srv.listener, srv.ntab))

	// This channel acts as a semaphore limiting
	// active inbound connections that are lingering pre-handshake.
	// If all slots are taken, no further connections are accepted.
	tokens := maxAcceptConns
	if srv.MaxPendingPeers > 0 {
		tokens = srv.MaxPendingPeers
	}
	slots := make(chan struct{}, tokens)
	for i := 0; i < tokens; i++ {
		slots <- struct{}{}
	}

	for {
		// Wait for a handshake slot before accepting.
		<-slots

		var (
			fd  net.Conn
			err error
		)
		for {
			fd, err = srv.listener.Accept()
			if tempErr, ok := err.(tempError); ok && tempErr.Temporary() {
				srv.log.Debug("Temporary read error", "err", err)
				continue
			} else if err != nil {
				srv.log.Debug("Read error", "err", err)
				return
			}
			break
		}

		// Reject connections that do not match NetRestrict.
		if srv.NetRestrict != nil {
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok && !srv.NetRestrict.Contains(tcp.IP) {
				srv.log.Debug("Rejected conn (not whitelisted in NetRestrict)", "addr", fd.RemoteAddr())
				fd.Close()
				slots <- struct{}{}
				continue
			}
		}

		fd = newMeteredConn(fd, true)
		srv.log.Trace("Accepted connection", "addr", fd.RemoteAddr())

		// Spawn the handler. It will give the slot back when the connection
		// has been established.
		go func() {
			srv.SetupConn(fd, inboundConn, nil)
			slots <- struct{}{}
		}()
	}
}

// SetupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *discover.Node) error {
	self := srv.Self()
	if self == nil {
		return errors.New("shutdown")
	}
	c := &conn{fd: fd, transport: srv.newTransport(fd), flags: flags, cont: make(chan error)}
	err := srv.setupConn(c, flags, dialDest)
	if err != nil {
		c.close(err)
		srv.log.Trace("Setting up connection failed", "id", c.id, "err", err)
	}
	return err
}

func (srv *Server) setupConn(c *conn, flags connFlag, dialDest *discover.Node, timeout ...time.Duration) error {
	// Prevent leftover pending conns from entering the handshake.
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	if !running {
		return errServerStopped
	}
	// Run the encryption handshake.
	var err error
	if c.id, err = c.doEncHandshake(srv.PrivateKey, dialDest); err != nil {
		srv.log.Trace("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return err
	}
	clog := srv.log.New("id", c.id, "conn", c.flags)
	// For dialed connections, check that the remote public key matches.
	if dialDest != nil && c.id != dialDest.ID {
		clog.Trace("Dialed identity mismatch", "want", c, dialDest.ID)
		return DiscUnexpectedIdentity
	}
	err = srv.checkpoint(c, srv.posthandshake, timeout...)
	if err != nil {
		clog.Trace("Rejected peer before protocol handshake", "err", err)
		return err
	}
	// Run the protocol handshake
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Trace("Failed proto handshake", "err", err)
		return err
	}
	if phs.ID != c.id {
		clog.Trace("Wrong devp2p handshake identity", "err", phs.ID)
		return DiscUnexpectedIdentity
	}
	c.caps, c.name = phs.Caps, phs.Name
	err = srv.checkpoint(c, srv.addpeer, timeout...)
	if err != nil {
		clog.Trace("Rejected peer", "err", err)
		return err
	}
	// If the checks completed successfully, runPeer has now been
	// launched by run.
	clog.Trace("connection set up", "inbound", dialDest == nil)
	return nil
}

func truncateName(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

// checkpoint sends the conn to run, which performs the
// post-handshake checks for the stage (posthandshake, addpeer).
func (srv *Server) checkpoint(c *conn, stage chan<- *conn, timeout ...time.Duration) error {
	tot := func() <-chan struct{} {
		rch := make(chan struct{})
		if len(timeout) > 0 && timeout[0] > 0 {
			go func() {
				<-time.After(timeout[0])
				close(rch)
			}()
		}
		return rch
	}
	select {
	case stage <- c:
	case <-srv.quit:
		return errServerStopped
	case <-tot():
		return errServerTimeout
	}
	select {
	case err := <-c.cont:
		return err
	case <-srv.quit:
		return errServerStopped
	case <-tot():
		return errServerTimeout
	}
}

// runPeer runs in its own goroutine for each peer.
// it waits until the Peer logic returns and removes
// the peer.
func (srv *Server) runPeer(p *Peer) {
	if srv.newPeerHook != nil {
		srv.newPeerHook(p)
	}

	// broadcast peer add
	srv.peerFeed.Send(&PeerEvent{
		Type: PeerEventTypeAdd,
		Peer: p.ID(),
	})

	// run the protocol
	remoteRequested, err := p.run()

	// broadcast peer drop
	srv.peerFeed.Send(&PeerEvent{
		Type:  PeerEventTypeDrop,
		Peer:  p.ID(),
		Error: err.Error(),
	})

	// Note: run waits for existing peers to be sent on srv.delpeer
	// before returning, so this send should not select on srv.quit.
	srv.delpeer <- peerDrop{p, err, remoteRequested}
}

// NodeInfo represents a short summary of the information known about the host.
type NodeInfo struct {
	ID    string `json:"id"`    // Unique node identifier (also the encryption key)
	Name  string `json:"name"`  // Name of the node, including client type, version, OS, custom data
	Enode string `json:"enode"` // Enode URL for adding this peer from remote peers
	IP    string `json:"ip"`    // IP address of the node
	Ports struct {
		Discovery int `json:"discovery"` // UDP listening port for discovery protocol
		Listener  int `json:"listener"`  // TCP listening port for RLPx
	} `json:"ports"`
	ListenAddr string                 `json:"listenAddr"`
	Protocols  map[string]interface{} `json:"protocols"`
}

// NodeInfo gathers and returns a collection of metadata known about the host.
func (srv *Server) NodeInfo() *NodeInfo {
	node := srv.Self()

	// Gather and assemble the generic node infos
	info := &NodeInfo{
		Name:       srv.Name,
		Enode:      node.String(),
		ID:         node.ID.String(),
		IP:         node.IP.String(),
		ListenAddr: srv.ListenAddr,
		Protocols:  make(map[string]interface{}),
	}
	info.Ports.Discovery = int(node.UDP)
	info.Ports.Listener = int(node.TCP)

	// Gather all the running protocol infos (only once per protocol type)
	for _, proto := range srv.Protocols {
		if _, ok := info.Protocols[proto.Name]; !ok {
			nodeInfo := interface{}("unknown")
			if query := proto.NodeInfo; query != nil {
				nodeInfo = proto.NodeInfo()
			}
			info.Protocols[proto.Name] = nodeInfo
		}
	}
	return info
}

// PeersInfo returns an array of metadata objects describing connected peers.
func (srv *Server) PeersInfo() []*PeerInfo {
	// Gather all the generic and sub-protocol specific infos
	infos := make([]*PeerInfo, 0, srv.PeerCount())
	for _, peer := range srv.Peers() {
		if peer != nil {
			infos = append(infos, peer.Info())
		}
	}
	// Sort the result array alphabetically by node identifier
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[i].ID > infos[j].ID {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
	return infos
}
