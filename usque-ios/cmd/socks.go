package cmd

import (
	"context"
	"log"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var socksCmd = &cobra.Command{
	Use:   "socks",
	Short: "Expose Warp as a SOCKS5 proxy",
	Long:  "Dual-stack SOCKS5 proxy with optional authentication. Doesn't require elevated privileges.",
	Run: func(cmd *cobra.Command, args []string) {
		if !config.ConfigLoaded {
			cmd.Println("Config not loaded. Please register first.")
			return
		}
		log.Println("Hint: l4-socks is faster for TCP-only SOCKS use cases.")

		sni, err := cmd.Flags().GetString("sni-address")
		if err != nil {
			cmd.Printf("Failed to get SNI address: %v\n", err)
			return
		}

		privKey, err := config.AppConfig.GetEcPrivateKey()
		if err != nil {
			cmd.Printf("Failed to get private key: %v\n", err)
			return
		}
		peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
		if err != nil {
			cmd.Printf("Failed to get public key: %v\n", err)
			return
		}

		cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			cmd.Printf("Failed to generate cert: %v\n", err)
			return
		}

		insecure, err := cmd.Flags().GetBool("insecure")
		if err != nil {
			cmd.Printf("Failed to get insecure flag: %v\n", err)
			return
		}

		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
		if err != nil {
			cmd.Printf("Failed to prepare TLS config: %v\n", err)
			return
		}

		keepalivePeriod, err := cmd.Flags().GetDuration("keepalive-period")
		if err != nil {
			cmd.Printf("Failed to get keepalive period: %v\n", err)
			return
		}
		initialPacketSize, err := cmd.Flags().GetUint16("initial-packet-size")
		if err != nil {
			cmd.Printf("Failed to get initial packet size: %v\n", err)
			return
		}

		bindAddress, err := cmd.Flags().GetString("bind")
		if err != nil {
			cmd.Printf("Failed to get bind address: %v\n", err)
			return
		}

		port, err := cmd.Flags().GetString("port")
		if err != nil {
			cmd.Printf("Failed to get port: %v\n", err)
			return
		}

		connectPort, err := cmd.Flags().GetInt("connect-port")
		if err != nil {
			cmd.Printf("Failed to get connect port: %v\n", err)
			return
		}

		useHTTP2, err := cmd.Flags().GetBool("http2")
		if err != nil {
			cmd.Printf("Failed to get HTTP/2 flag: %v\n", err)
			return
		}

		quicSplit, err := cmd.Flags().GetBool("quic-split")
		if err != nil {
			cmd.Printf("Failed to get quic-split flag: %v\n", err)
			return
		}
		quicReorder, err := cmd.Flags().GetBool("quic-reorder")
		if err != nil {
			cmd.Printf("Failed to get quic-reorder flag: %v\n", err)
			return
		}

		udpSpoofPreset, err := cmd.Flags().GetString("udp-spoof")
		if err != nil {
			cmd.Printf("Failed to get udp-spoof flag: %v\n", err)
			return
		}
		udpSpoof, err := api.UDPSpoofPreset(udpSpoofPreset)
		if err != nil {
			cmd.Printf("%v\n", err)
			return
		}
		if useHTTP2 {
			udpSpoof = api.UDPSpoof{}
		} else {
			if quicSplit {
				udpSpoof.Split = true
			}
			if quicReorder {
				udpSpoof.Reorder = true
			}
		}
		udpSpoof.SNI = sni

		useIPv6, err := cmd.Flags().GetBool("ipv6")
		if err != nil {
			cmd.Printf("Failed to get ipv6 flag: %v\n", err)
			return
		}

		endpoint, err := config.SelectEndpointFromConfig(useHTTP2, useIPv6, connectPort)
		if err != nil {
			cmd.Printf("Failed to select endpoint: %v\n", err)
			return
		}

		if insecure {
			config.WarnInsecure()
		}

		if useHTTP2 {
			config.LogHTTP2Endpoint(endpoint)
		}

		tunnelIPv4, err := cmd.Flags().GetBool("no-tunnel-ipv4")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv4: %v\n", err)
			return
		}

		tunnelIPv6, err := cmd.Flags().GetBool("no-tunnel-ipv6")
		if err != nil {
			cmd.Printf("Failed to get no tunnel IPv6: %v\n", err)
			return
		}

		var localAddresses []netip.Addr
		if !tunnelIPv4 {
			v4, err := netip.ParseAddr(config.AppConfig.IPv4)
			if err != nil {
				cmd.Printf("Failed to parse IPv4 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v4)
		}
		if !tunnelIPv6 {
			v6, err := netip.ParseAddr(config.AppConfig.IPv6)
			if err != nil {
				cmd.Printf("Failed to parse IPv6 address: %v\n", err)
				return
			}
			localAddresses = append(localAddresses, v6)
		}

		dnsServers, err := cmd.Flags().GetStringArray("dns")
		if err != nil {
			cmd.Printf("Failed to get DNS servers: %v\n", err)
			return
		}

		var dnsAddrs []netip.Addr
		for _, dns := range dnsServers {
			addr, err := netip.ParseAddr(dns)
			if err != nil {
				cmd.Printf("Failed to parse DNS server: %v\n", err)
				return
			}
			dnsAddrs = append(dnsAddrs, addr)
		}

		var dnsTimeout time.Duration
		if dnsTimeout, err = cmd.Flags().GetDuration("dns-timeout"); err != nil {
			cmd.Printf("Failed to get DNS timeout: %v\n", err)
			return
		}

		localDNS, err := cmd.Flags().GetBool("local-dns")
		if err != nil {
			cmd.Printf("Failed to get local-dns flag: %v\n", err)
			return
		}

		systemDNS, err := cmd.Flags().GetBool("system-dns")
		if err != nil {
			cmd.Printf("Failed to get system-dns flag: %v\n", err)
			return
		}
		if systemDNS && !localDNS {
			log.Println("Warning: --system-dns only applies with -l; ignoring")
			systemDNS = false
		}

		mtu, err := cmd.Flags().GetInt("mtu")
		if err != nil {
			cmd.Printf("Failed to get MTU: %v\n", err)
			return
		}
		if mtu != 1280 {
			log.Println("Warning: MTU is not the default 1280. This is not supported. Packet loss and other issues may occur.")
		}

		var username string
		var password string
		if u, err := cmd.Flags().GetString("username"); err == nil && u != "" {
			username = u
		}
		if p, err := cmd.Flags().GetString("password"); err == nil && p != "" {
			password = p
		}

		reconnectDelay, err := cmd.Flags().GetDuration("reconnect-delay")
		if err != nil {
			cmd.Printf("Failed to get reconnect delay: %v\n", err)
			return
		}

		udpTimeout, err := cmd.Flags().GetDuration("udp-timeout")
		if err != nil {
			cmd.Printf("Failed to get UDP timeout: %v\n", err)
			return
		}
		if udpTimeout <= 0 {
			log.Println("Warning: --udp-timeout is 0; idle UDP ASSOCIATE exchanges will never expire. Memory will grow under heavy UDP traffic (DHT, uTP, etc.).")
		}

		alwaysReconnect, err := cmd.Flags().GetBool("always-reconnect")
		if err != nil {
			cmd.Printf("Failed to get always-reconnect flag: %v\n", err)
			return
		}

		useUTLS, err := cmd.Flags().GetBool("utls")
		if err != nil {
			cmd.Printf("Failed to get utls flag: %v\n", err)
			return
		}
		h2Pad, err := cmd.Flags().GetBool("h2-pad")
		if err != nil {
			cmd.Printf("Failed to get h2-pad flag: %v\n", err)
			return
		}
		recordSplit, err := cmd.Flags().GetBool("record-split")
		if err != nil {
			cmd.Printf("Failed to get record-split flag: %v\n", err)
			return
		}
		splitHost, err := cmd.Flags().GetBool("split-host")
		if err != nil {
			cmd.Printf("Failed to get split-host flag: %v\n", err)
			return
		}
		tcpSplit, err := cmd.Flags().GetBool("tcp-split")
		if err != nil {
			cmd.Printf("Failed to get tcp-split flag: %v\n", err)
			return
		}
		if splitHost {
			recordSplit = true
		}
		if recordSplit {
			tcpSplit = false
		}
		if (useUTLS || h2Pad || recordSplit || splitHost || tcpSplit) && !useHTTP2 {
			log.Println("Warning: --utls, --h2-pad, --record-split, --split-host, and --tcp-split apply to MASQUE TCP only; ignoring")
			useUTLS = false
			h2Pad = false
			recordSplit = false
			splitHost = false
			tcpSplit = false
		}

		trace, err := cmd.Flags().GetBool("trace")
		if err != nil {
			cmd.Printf("Failed to get trace flag: %v\n", err)
			return
		}

		onConnect, err := cmd.Flags().GetString("on-connect")
		if err != nil {
			cmd.Printf("Failed to get on-connect flag: %v\n", err)
			return
		}

		onDisconnect, err := cmd.Flags().GetString("on-disconnect")
		if err != nil {
			cmd.Printf("Failed to get on-disconnect flag: %v\n", err)
			return
		}

		hookEnv := map[string]string{
			"USQUE_MODE": "socks",
			"USQUE_IPV4": config.AppConfig.IPv4,
			"USQUE_IPV6": config.AppConfig.IPv6,
		}

		tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, mtu)
		if err != nil {
			cmd.Printf("Failed to create virtual TUN device: %v\n", err)
			return
		}
		defer func() { _ = tunDev.Close() }()

		go api.MaintainTunnel(context.Background(), api.MaintainTunnelConfig{
			TLSConfig:         tlsConfig,
			KeepalivePeriod:   keepalivePeriod,
			InitialPacketSize: initialPacketSize,
			Endpoint:          endpoint,
			Device:            api.NewNetstackAdapter(tunDev),
			MTU:               mtu,
			ReconnectDelay:    reconnectDelay,
			AlwaysReconnect:   alwaysReconnect,
			UseHTTP2:          useHTTP2,
			H2Spoof:           api.H2Spoof{RecordSplit: recordSplit, SplitAtHost: splitHost, UTLS: useUTLS, H2Pad: h2Pad, TcpSplit: tcpSplit},
			UDPSpoof:          udpSpoof,
			OnConnect:         onConnect,
			OnDisconnect:      onDisconnect,
			HookEnv:           hookEnv,
			Trace:             trace,
		})

		resolver := &internal.TunnelDNSResolver{
			DNSAddrs:      dnsAddrs,
			Timeout:       dnsTimeout,
			UseOSResolver: localDNS && systemDNS,
		}
		if !localDNS {
			resolver.TunNet = tunNet
		}

		server, err := internal.NewSOCKS5Server(internal.SOCKS5Config{
			Addr:       net.JoinHostPort(bindAddress, port),
			Username:   username,
			Password:   password,
			Resolver:   resolver,
			TunNet:     tunNet,
			UDPTimeout: udpTimeout,
			Logger:     log.New(internal.NewTZStampWriter(os.Stderr), "socks5: ", 0),
			Trace:      trace,
		})
		if err != nil {
			cmd.Printf("Failed to create SOCKS proxy: %v\n", err)
			return
		}

		log.Printf("SOCKS proxy listening on %s:%s", bindAddress, port)
		if err := server.Start(); err != nil {
			cmd.Printf("Failed to start SOCKS proxy: %v\n", err)
			return
		}
	},
}

func init() {
	socksCmd.Flags().StringP("bind", "b", "0.0.0.0", "Address to bind the SOCKS proxy to")
	socksCmd.Flags().StringP("port", "p", "1080", "Port to listen on for SOCKS proxy")
	socksCmd.Flags().StringP("username", "u", "", "Username for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().StringP("password", "w", "", "Password for proxy authentication (specify both username and password to enable)")
	socksCmd.Flags().IntP("connect-port", "P", 443, "Used port for MASQUE connection")
	socksCmd.Flags().StringArrayP("dns", "d", []string{"9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"}, "DNS servers for the tunnel stack; with -l also used for SOCKS name lookups (unless --system-dns)")
	socksCmd.Flags().DurationP("dns-timeout", "t", 2*time.Second, "Timeout for DNS queries")
	socksCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 for MASQUE connection")
	socksCmd.Flags().BoolP("no-tunnel-ipv4", "F", false, "Disable IPv4 inside the MASQUE tunnel")
	socksCmd.Flags().BoolP("no-tunnel-ipv6", "S", false, "Disable IPv6 inside the MASQUE tunnel")
	socksCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address to use for MASQUE connection")
	socksCmd.Flags().DurationP("keepalive-period", "k", 30*time.Second, "Keepalive period for MASQUE connection")
	socksCmd.Flags().IntP("mtu", "m", 1280, "MTU for MASQUE connection")
	socksCmd.Flags().Uint16P("initial-packet-size", "i", 0, "Custom initial packet size for MASQUE connection (default: auto with PMTU discovery)")
	socksCmd.Flags().DurationP("reconnect-delay", "r", 1*time.Second, "Delay between reconnect attempts")
	socksCmd.Flags().Duration("udp-timeout", 60*time.Second, "Idle read deadline for each remote UDP relay (SOCKS5 ASSOCIATE). Shorter frees memory sooner; raise (e.g. 300s) if a quiet peer needs longer silence. 0 disables the deadline and risks unbounded growth under DHT/uTP")
	socksCmd.Flags().Bool("always-reconnect", false, "Always reconnect after tunnel loss, even when idle")
	socksCmd.Flags().Bool("http2", false, "Use HTTP/2 over TCP+TLS instead of HTTP/3 over QUIC."+config.EndpointHelpSuffixH2)
	socksCmd.Flags().Bool("utls", false, "MASQUE TCP spoof: Chrome ClientHello. Off uses the stock Go handshake")
	socksCmd.Flags().Bool("h2-pad", false, "MASQUE TCP spoof: split the first HTTP/2 TLS records. Off leaves record sizes unchanged")
	socksCmd.Flags().Bool("record-split", false, "MASQUE TCP spoof: rewrap the ClientHello as two TLS records. Off sends one record")
	socksCmd.Flags().Bool("split-host", false, "MASQUE TCP spoof: cut the ClientHello through the SNI hostname. Off keeps the middle cut")
	socksCmd.Flags().Bool("tcp-split", false, "MASQUE TCP spoof: send one ClientHello as two TCP segments, cut through the hostname. Off sends one segment")
	socksCmd.Flags().Bool("quic-split", false, "MASQUE UDP spoof: send the QUIC ClientHello in two Initial packets. Off sends one Initial")
	socksCmd.Flags().Bool("quic-reorder", false, "MASQUE UDP spoof: send the later ClientHello bytes, including the hostname, before the earlier bytes")
	socksCmd.Flags().String("udp-spoof", "", "MASQUE UDP spoof: send junk and decoy datagrams before each QUIC Initial (junk, quic, dns_stun, junk_quic, full). Empty sends none")
	socksCmd.Flags().Bool("trace", false, "Log every SOCKS TCP connection and per-second tunnel packet counts")
	socksCmd.Flags().Bool("insecure", false, "Disable endpoint certificate pinning and trust any certificate")
	socksCmd.Flags().BoolP("local-dns", "l", false, "Do not send proxy DNS through the tunnel; use -d over the host instead. Add --system-dns to use the OS resolver instead of -d")
	socksCmd.Flags().Bool("system-dns", false, "With -l, resolve names via the OS (e.g. /etc/resolv.conf) instead of -d")
	socksCmd.Flags().String("on-connect", "", "Path to an executable to run after each successful tunnel connect (no args; context via USQUE_* env vars)")
	socksCmd.Flags().String("on-disconnect", "", "Path to an executable to run after each tunnel disconnect (no args; context via USQUE_* env vars)")
	rootCmd.AddCommand(socksCmd)
}
