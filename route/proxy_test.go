package route

import (
	"crypto/tls"
	"net/http"
	"reflect"
	"testing"
)

func TestAddHeaders(t *testing.T) {
	tests := []struct {
		r              *http.Request
		localIP        string
		remoteIPHeader string
		tlsHeader      string
		tlsHeaderValue string
		hdrs           http.Header
		err            string
	}{
		{ // error
			&http.Request{RemoteAddr: "1.2.3.4"},
			"", "", "", "",
			http.Header{},
			"cannot parse 1.2.3.4",
		},

		{ // set remote ip header
			&http.Request{RemoteAddr: "1.2.3.4:5555"},
			"", "Client-IP", "", "",
			http.Header{"Forwarded": {"for=1.2.3.4; proto=http"}, "Client-Ip": []string{"1.2.3.4"}},
			"",
		},

		{ // set remote ip header with local ip (no change expected)
			&http.Request{RemoteAddr: "1.2.3.4:5555"},
			"5.6.7.8", "Client-IP", "", "",
			http.Header{"Forwarded": {"for=1.2.3.4; proto=http; by=5.6.7.8"}, "Client-Ip": []string{"1.2.3.4"}},
			"",
		},

		{ // set X-Forwarded-For
			&http.Request{RemoteAddr: "1.2.3.4:5555"},
			"", "X-Forwarded-For", "", "",
			http.Header{"Forwarded": {"for=1.2.3.4; proto=http"}, "X-Forwarded-For": []string{"1.2.3.4"}},
			"",
		},

		{ // set X-Forwarded-For with local ip
			&http.Request{RemoteAddr: "1.2.3.4:5555"},
			"5.6.7.8", "X-Forwarded-For", "", "",
			http.Header{"Forwarded": {"for=1.2.3.4; proto=http; by=5.6.7.8"}, "X-Forwarded-For": []string{"1.2.3.4, 5.6.7.8"}},
			"",
		},

		{ // extend X-Forwarded-For with local ip
			&http.Request{RemoteAddr: "1.2.3.4:5555", Header: http.Header{"X-Forwarded-For": []string{"9.9.9.9"}}},
			"5.6.7.8", "", "", "",
			http.Header{"Forwarded": {"for=1.2.3.4; proto=http; by=5.6.7.8"}, "X-Forwarded-For": []string{"9.9.9.9, 5.6.7.8"}},
			"",
		},

		{ // set Forwarded
			&http.Request{RemoteAddr: "1.2.3.4:5555"},
			"", "", "", "",
			http.Header{"Forwarded": {"for=1.2.3.4; proto=http"}},
			"",
		},

		{ // set Forwarded with localIP
			&http.Request{RemoteAddr: "1.2.3.4:5555"},
			"5.6.7.8", "", "", "",
			http.Header{"Forwarded": {"for=1.2.3.4; proto=http; by=5.6.7.8"}},
			"",
		},

		{ // set Forwarded with localIP and HTTPS
			&http.Request{RemoteAddr: "1.2.3.4:5555", TLS: &tls.ConnectionState{}},
			"5.6.7.8", "", "", "",
			http.Header{"Forwarded": {"for=1.2.3.4; proto=https; by=5.6.7.8"}},
			"",
		},

		{ // extend Forwarded with localIP
			&http.Request{RemoteAddr: "1.2.3.4:5555", Header: http.Header{"Forwarded": {"for=9.9.9.9; proto=http; by=8.8.8.8"}}},
			"5.6.7.8", "", "", "",
			http.Header{"Forwarded": {"for=9.9.9.9; proto=http; by=8.8.8.8; by=5.6.7.8"}},
			"",
		},

		{ // set tls header
			&http.Request{RemoteAddr: "1.2.3.4:5555", TLS: &tls.ConnectionState{}},
			"5.6.7.8", "", "Secure", "",
			http.Header{"Forwarded": {"for=1.2.3.4; proto=https; by=5.6.7.8"}, "Secure": {""}},
			"",
		},

		{ // set tls header with value
			&http.Request{RemoteAddr: "1.2.3.4:5555", TLS: &tls.ConnectionState{}},
			"5.6.7.8", "", "Secure", "true",
			http.Header{"Forwarded": {"for=1.2.3.4; proto=https; by=5.6.7.8"}, "Secure": {"true"}},
			"",
		},
	}

	for i, tt := range tests {
		if tt.r.Header == nil {
			tt.r.Header = http.Header{}
		}

		err := addHeaders(tt.r, tt.localIP, tt.remoteIPHeader, tt.tlsHeader, tt.tlsHeaderValue)
		if err != nil {
			if got, want := err.Error(), tt.err; got != want {
				t.Errorf("%d: got %q want %q", i, got, want)
			}
			continue
		}
		if tt.err != "" {
			t.Errorf("%d: got nil want %q", i, tt.err)
			continue
		}
		if got, want := tt.r.Header, tt.hdrs; !reflect.DeepEqual(got, want) {
			t.Errorf("%d: got %v want %v", i, got, want)
		}
	}
}
