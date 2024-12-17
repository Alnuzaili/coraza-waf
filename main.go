package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type ProtectedSite struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	URL    string `json:"url"`
	Active bool   `json:"active"`
}

type LogMessage struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

type WAFBlockPage struct {
	Message    string
	RuleID     string
	Severity   string
	IncidentID string
}

var (
	sites     = make(map[string]*ProtectedSite)
	sitesLock sync.RWMutex
	upgrader  = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	logClients = make(map[*websocket.Conn]bool)
	logLock    sync.RWMutex
	templates  *template.Template
)

func generateIncidentID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func init() {
	var err error
	templates, err = template.ParseGlob("templates/*.html")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	r := mux.NewRouter()

	// Static files
	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Dashboard routes
	r.HandleFunc("/", dashboardHandler).Methods("GET")
	r.HandleFunc("/api/sites", listSitesHandler).Methods("GET")
	r.HandleFunc("/api/sites", addSiteHandler).Methods("POST")
	r.HandleFunc("/api/sites/{id}", deleteSiteHandler).Methods("DELETE")
	r.HandleFunc("/ws/logs", websocketHandler)

	// Protected sites handler
	r.PathPrefix("/proxy/").Handler(http.HandlerFunc(proxyHandler))

	fmt.Println("Server is running. Dashboard available at: http://localhost:8090")
	log.Fatal(http.ListenAndServe(":8090", r))
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/dashboard.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func listSitesHandler(w http.ResponseWriter, r *http.Request) {
	sitesLock.RLock()
	sitesList := make([]ProtectedSite, 0, len(sites))
	for _, site := range sites {
		sitesList = append(sitesList, *site)
	}
	sitesLock.RUnlock()

	json.NewEncoder(w).Encode(sitesList)
}

func addSiteHandler(w http.ResponseWriter, r *http.Request) {
	var site ProtectedSite
	if err := json.NewDecoder(r.Body).Decode(&site); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sitesLock.Lock()
	site.ID = fmt.Sprintf("site_%d", len(sites)+1)
	site.Active = true
	sites[site.ID] = &site
	sitesLock.Unlock()

	broadcastLogMessage(LogMessage{
		Level:   "info",
		Message: fmt.Sprintf("Added new protected site: %s (%s)", site.Name, site.URL),
	})

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(site)
}

func deleteSiteHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	sitesLock.Lock()
	if site, exists := sites[id]; exists {
		delete(sites, id)
		broadcastLogMessage(LogMessage{
			Level:   "info",
			Message: fmt.Sprintf("Removed protected site: %s (%s)", site.Name, site.URL),
		})
	}
	sitesLock.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

func websocketHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("Websocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	logLock.Lock()
	logClients[conn] = true
	logLock.Unlock()

	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			logLock.Lock()
			delete(logClients, conn)
			logLock.Unlock()
			break
		}
	}
}

func broadcastLogMessage(msg LogMessage) {
	logLock.RLock()
	for client := range logClients {
		if err := client.WriteJSON(msg); err != nil {
			log.Printf("Error broadcasting to client: %v", err)
		}
	}
	logLock.RUnlock()
}

func createWAF() coraza.WAF {
	directivesFile := "./default.conf"
	if s := os.Getenv("DIRECTIVES_FILE"); s != "" {
		directivesFile = s
	}

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(logError).
			WithDirectivesFromFile(directivesFile),
	)
	if err != nil {
		log.Fatal(err)
	}
	return waf
}

func logError(error types.MatchedRule) {
	incidentID := generateIncidentID()
	msg := fmt.Sprintf("[WAF BLOCK] Rule ID: %d, Message: %s, Incident ID: %s",
		error.Rule().ID(),
		error.ErrorLog(),
		incidentID)

	broadcastLogMessage(LogMessage{
		Level:   string(error.Rule().Severity()),
		Message: msg,
	})

	log.Printf("\n=== WAF Security Event ===\n")
	log.Printf("Incident ID: %s\n", incidentID)
	log.Printf("Rule ID: %d\n", error.Rule().ID())
	log.Printf("Severity: %s\n", error.Rule().Severity())
	log.Printf("Message: %s\n", error.ErrorLog())
	log.Printf("========================\n")
}

// func wafErrorHandler(w http.ResponseWriter, r *http.Request) {
// 	incidentID := generateIncidentID()
// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
// 	w.WriteHeader(http.StatusForbidden)
// 	if err := templates.ExecuteTemplate(w, "403.html", WAFBlockPage{
// 		Message:    "Request blocked by WAF",
// 		RuleID:     "N/A",
// 		Severity:   "CRITICAL",
// 		IncidentID: incidentID,
// 	}); err != nil {
// 		log.Printf("Error rendering 403 template: %v", err)
// 		http.Error(w, "Forbidden", http.StatusForbidden)
// 	}
// }

func wafErrorHandler(w http.ResponseWriter, r *http.Request) {
	incidentID := generateIncidentID()
	blockPage := WAFBlockPage{
		Message:    "Request blocked by WAF",
		RuleID:     "N/A",
		Severity:   "CRITICAL",
		IncidentID: incidentID,
	}

	// Buffer the response to handle template errors gracefully
	var responseBuffer bytes.Buffer

	// Attempt to execute the template into the buffer
	err := templates.ExecuteTemplate(&responseBuffer, "403.html", blockPage)
	if err != nil {
		log.Printf("Error rendering 403 template: %v", err)

		// Provide fallback content if the template fails
		responseBuffer.WriteString(`
			<html>
			<head><title>403 Forbidden</title></head>
			<body>
				<h1>403 Forbidden</h1>
				<p>Request blocked by WAF.</p>
				<p>Incident ID: ` + incidentID + `</p>
			</body>
			</html>
		`)
	}

	// Write the final response
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(responseBuffer.Len()))
	w.WriteHeader(http.StatusForbidden)
	_, writeErr := w.Write(responseBuffer.Bytes())
	if writeErr != nil {
		log.Printf("Error writing response: %v", writeErr)
	}
}

func proxyHandler(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/proxy/"), "/", 2)
	if len(parts) == 0 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	siteID := parts[0]
	remainingPath := ""
	if len(parts) > 1 {
		remainingPath = "/" + parts[1]
	}

	sitesLock.RLock()
	site, exists := sites[siteID]
	sitesLock.RUnlock()

	if !exists {
		http.Error(w, "Site not found", http.StatusNotFound)
		return
	}

	targetURL, err := url.Parse(site.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			if req.URL.Scheme == "" {
				req.URL.Scheme = "http"
			}
			req.URL.Host = targetURL.Host
			req.URL.Path = remainingPath
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}
			req.Host = targetURL.Host

			req.URL.RawQuery = r.URL.RawQuery

			if _, ok := req.Header["User-Agent"]; !ok {
				req.Header.Set("User-Agent", "")
			}

			log.Printf("Proxying request to: %s", req.URL.String())
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Set("Access-Control-Allow-Origin", "*")
			resp.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			resp.Header.Set("Access-Control-Allow-Headers", "*")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Proxy error: %v", err)
			wafErrorHandler(w, r)
		},
	}

	waf := createWAF()
	handler := txhttp.WrapHandler(waf, proxy)
	handler.ServeHTTP(w, r)
}
