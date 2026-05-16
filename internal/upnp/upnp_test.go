package upnp

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestFetchControlURL_FromDeviceDescription drives the XML parsing path with
// a stubbed device description served by httptest.
func TestFetchControlURL_FromDeviceDescription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0"?>
<root>
  <device>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <deviceList>
          <device>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/igd-control</controlURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>`))
	}))
	defer srv.Close()

	igd, err := fetchControlURL(srv.URL + "/description.xml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(igd.ControlURL, "/igd-control") {
		t.Errorf("ControlURL = %q", igd.ControlURL)
	}
	if !strings.Contains(igd.ServiceType, "WANIPConnection") {
		t.Errorf("ServiceType = %q", igd.ServiceType)
	}
}

// TestAddPortMapping_SOAPBody verifies the SOAP envelope is well-formed and
// hits the configured control URL with the right action header.
func TestAddPortMapping_SOAPBody(t *testing.T) {
	var gotBody string
	var gotAction string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		gotAction = r.Header.Get("SOAPAction")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<?xml version="1.0"?><s:Envelope/>`))
	}))
	defer srv.Close()

	igd := &IGD{
		ControlURL:  srv.URL,
		ServiceType: "urn:schemas-upnp-org:service:WANIPConnection:1",
		LocalIP:     []byte{192, 168, 1, 100},
	}
	err := igd.AddPortMapping(context.Background(), "UDP", 51820, 51820, "gsnet test", 3600)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotAction, "AddPortMapping") {
		t.Errorf("SOAPAction = %q", gotAction)
	}
	// Validate body parses as XML and contains the right port.
	var dummy struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal([]byte(gotBody), &dummy); err != nil {
		t.Errorf("body did not parse as XML: %v", err)
	}
	if !strings.Contains(gotBody, "<NewExternalPort>51820</NewExternalPort>") {
		t.Errorf("body missing external port: %s", gotBody)
	}
	if !strings.Contains(gotBody, "<NewInternalClient>192.168.1.100</NewInternalClient>") {
		t.Errorf("body missing internal client: %s", gotBody)
	}
}
