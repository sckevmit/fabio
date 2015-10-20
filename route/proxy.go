package route

import (
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	gometrics "github.com/eBay/fabio/_third_party/github.com/rcrowley/go-metrics"
)

// Proxy is a dynamic reverse proxy.
type Proxy struct {
	tr             http.RoundTripper
	localIP        string
	clientIPHeader string
	tlsHeader      string
	tlsHeaderValue string
	requests       gometrics.Timer
}

func NewProxy(tr http.RoundTripper, localIP, clientIPHeader, tlsHeader, tlsHeaderValue string) *Proxy {
	return &Proxy{
		tr:             tr,
		localIP:        localIP,
		clientIPHeader: clientIPHeader,
		tlsHeader:      tlsHeader,
		tlsHeaderValue: tlsHeaderValue,
		requests:       gometrics.GetOrRegisterTimer("requests", gometrics.DefaultRegistry),
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if ShuttingDown() {
		http.Error(w, "shutting down", http.StatusServiceUnavailable)
		return
	}

	target := GetTable().lookup(req, req.Header.Get("trace"))
	if target == nil {
		log.Print("[WARN] No route for ", req.URL)
		w.WriteHeader(404)
		return
	}

	if err := addHeaders(req, p.localIP, p.clientIPHeader, p.tlsHeader, p.tlsHeaderValue); err != nil {
		http.Error(w, "cannot parse "+req.RemoteAddr, http.StatusInternalServerError)
		return
	}

	start := time.Now()
	rp := httputil.NewSingleHostReverseProxy(target.URL)
	rp.Transport = p.tr
	rp.ServeHTTP(w, req)
	target.timer.UpdateSince(start)
	p.requests.UpdateSince(start)
}

func addHeaders(r *http.Request, localIP, clientIPHeader, tlsHeader, tlsHeaderValue string) error {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return errors.New("cannot parse " + r.RemoteAddr)
	}

	if clientIPHeader != "" {
		r.Header.Set(clientIPHeader, remoteIP)
	}

	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" && localIP != "" {
		r.Header.Set("X-Forwarded-For", xff+", "+localIP)
	}

	fwd := r.Header.Get("Forwarded")
	if fwd == "" {
		fwd = "for=" + remoteIP
		if r.TLS != nil {
			fwd += "; proto=https"
		} else {
			fwd += "; proto=http"
		}
	}
	if localIP != "" {
		fwd += "; by=" + localIP
	}
	r.Header.Set("Forwarded", fwd)

	if tlsHeader != "" && r.TLS != nil {
		r.Header.Set(tlsHeader, tlsHeaderValue)
	}

	return nil
}
