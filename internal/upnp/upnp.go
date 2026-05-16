// Package upnp is a minimal UPnP-IGD client. It discovers an Internet
// Gateway Device on the LAN via SSDP M-SEARCH, reads the device description,
// and invokes the AddPortMapping action so a single port forward survives
// for the duration the daemon is running.
//
// Scope: this is the smallest implementation that does something useful for
// gsnet (one UDP port mapping). It is not a general SOAP/UPnP toolkit.
package upnp

import (
	"bufio"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IGD is a discovered Internet Gateway Device.
type IGD struct {
	ControlURL  string // e.g. http://192.168.1.1:5000/igd-control
	ServiceType string // e.g. urn:schemas-upnp-org:service:WANIPConnection:1
	LocalIP     net.IP // address of the interface we used to reach the gateway
}

// Discover sends an SSDP M-SEARCH and returns the first IGD that responds
// with a valid description. Returns an error if none responds within timeout.
func Discover(ctx context.Context, timeout time.Duration) (*IGD, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	mcast := &net.UDPAddr{IP: net.ParseIP("239.255.255.250"), Port: 1900}

	const search = "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
	if _, err := conn.WriteTo([]byte(search), mcast); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	_ = conn.SetReadDeadline(deadline)

	buf := make([]byte, 8192)
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, fmt.Errorf("ssdp: no IGD found: %w", err)
		}
		hdrs, err := parseSSDPHeaders(buf[:n])
		if err != nil {
			continue
		}
		loc := hdrs["LOCATION"]
		if loc == "" {
			continue
		}
		igd, err := fetchControlURL(loc)
		if err != nil {
			continue
		}
		// LocalIP = the interface that holds the route to raddr.
		if local := localIPTo(raddr.IP); local != nil {
			igd.LocalIP = local
		}
		return igd, nil
	}
}

func parseSSDPHeaders(b []byte) (map[string]string, error) {
	out := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(string(b)))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, ":"); i > 0 {
			out[strings.ToUpper(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
		}
	}
	return out, nil
}

func localIPTo(remote net.IP) net.IP {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remote, Port: 9})
	if err != nil {
		return nil
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}

// deviceDesc is the subset of the device description XML we need.
type deviceDesc struct {
	Device struct {
		DeviceList struct {
			Device []innerDevice `xml:"device"`
		} `xml:"deviceList"`
	} `xml:"device"`
}

type innerDevice struct {
	DeviceType  string `xml:"deviceType"`
	ServiceList struct {
		Service []service `xml:"service"`
	} `xml:"serviceList"`
	DeviceList struct {
		Device []innerDevice `xml:"device"`
	} `xml:"deviceList"`
}

type service struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}

func fetchControlURL(locationURL string) (*IGD, error) {
	resp, err := http.Get(locationURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var dd deviceDesc
	if err := xml.Unmarshal(body, &dd); err != nil {
		return nil, err
	}
	svc, found := findWANConnection(dd.Device.DeviceList.Device)
	if !found {
		return nil, fmt.Errorf("upnp: no WANIPConnection/WANPPPConnection service")
	}
	control := svc.ControlURL
	if !strings.HasPrefix(control, "http") {
		base, err := url.Parse(locationURL)
		if err != nil {
			return nil, err
		}
		ref, err := url.Parse(control)
		if err != nil {
			return nil, err
		}
		control = base.ResolveReference(ref).String()
	}
	return &IGD{ControlURL: control, ServiceType: svc.ServiceType}, nil
}

func findWANConnection(devs []innerDevice) (service, bool) {
	for _, d := range devs {
		for _, s := range d.ServiceList.Service {
			if strings.Contains(s.ServiceType, "WANIPConnection") || strings.Contains(s.ServiceType, "WANPPPConnection") {
				return s, true
			}
		}
		if svc, ok := findWANConnection(d.DeviceList.Device); ok {
			return svc, true
		}
	}
	return service{}, false
}

// AddPortMapping installs a UDP or TCP port forward at the gateway.
//   proto: "UDP" or "TCP"
//   externalPort: port on the gateway's WAN side
//   internalPort: port on the LAN host
//   leaseSec: 0 means permanent (some routers reject this; prefer 3600+)
func (g *IGD) AddPortMapping(ctx context.Context, proto string, externalPort, internalPort int, description string, leaseSec int) error {
	if g.LocalIP == nil {
		return fmt.Errorf("upnp: LocalIP unknown")
	}
	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:AddPortMapping xmlns:u="%s">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
<NewInternalPort>%d</NewInternalPort>
<NewInternalClient>%s</NewInternalClient>
<NewEnabled>1</NewEnabled>
<NewPortMappingDescription>%s</NewPortMappingDescription>
<NewLeaseDuration>%d</NewLeaseDuration>
</u:AddPortMapping>
</s:Body>
</s:Envelope>`, g.ServiceType, externalPort, proto, internalPort, g.LocalIP, description, leaseSec)

	req, err := http.NewRequestWithContext(ctx, "POST", g.ControlURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+g.ServiceType+`#AddPortMapping"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		rbody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upnp: AddPortMapping HTTP %d: %s", resp.StatusCode, rbody)
	}
	return nil
}

// GetExternalIPAddress fetches the WAN-side IP the gateway is using.
func (g *IGD) GetExternalIPAddress(ctx context.Context) (string, error) {
	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:GetExternalIPAddress xmlns:u="%s"></u:GetExternalIPAddress>
</s:Body>
</s:Envelope>`, g.ServiceType)
	req, err := http.NewRequestWithContext(ctx, "POST", g.ControlURL, strings.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+g.ServiceType+`#GetExternalIPAddress"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	rbody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("upnp: GetExternalIPAddress HTTP %d: %s", resp.StatusCode, rbody)
	}
	// Parse minimal SOAP envelope.
	var env struct {
		Body struct {
			Resp struct {
				IP string `xml:"NewExternalIPAddress"`
			} `xml:"GetExternalIPAddressResponse"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(rbody, &env); err != nil {
		return "", err
	}
	if env.Body.Resp.IP == "" {
		return "", fmt.Errorf("upnp: empty NewExternalIPAddress in response")
	}
	return env.Body.Resp.IP, nil
}

// DeletePortMapping removes a previously-installed mapping.
func (g *IGD) DeletePortMapping(ctx context.Context, proto string, externalPort int) error {
	body := fmt.Sprintf(`<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:DeletePortMapping xmlns:u="%s">
<NewRemoteHost></NewRemoteHost>
<NewExternalPort>%d</NewExternalPort>
<NewProtocol>%s</NewProtocol>
</u:DeletePortMapping>
</s:Body>
</s:Envelope>`, g.ServiceType, externalPort, proto)
	req, err := http.NewRequestWithContext(ctx, "POST", g.ControlURL, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+g.ServiceType+`#DeletePortMapping"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		rbody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upnp: DeletePortMapping HTTP %d: %s", resp.StatusCode, rbody)
	}
	return nil
}
