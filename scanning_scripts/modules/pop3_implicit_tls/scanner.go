package pop3_implicit_tls

import (
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/zmap/zgrab2"
)

// ScanResults instances are returned by the module's Scan function.
type ScanResults struct {
	// Greeting is the targets greeting message
	Greeting string `json:"help,omitempty"`

	// Capabilities is the targets response to CAPA
	Capabilities string `json:"Capabilities,omitempty"`

	// Trace is the complete communication between client and server
	Trace []string `json:"trace"`

	// Status is the step, the execution of the Scan ended in (used for debug)
	Status int `json:"status,omitempty"`

	// TLSLog is the standard TLS log
	TLSLog *zgrab2.TLSLog `json:"tls,omitempty"`
}

// Flags holds the command-line configuration for the IMAP scan module.
// Populated by the framework.
type Flags struct {
	zgrab2.BaseFlags
	zgrab2.TLSFlags

	// Verbose indicates that there should be more verbose logging.
	Verbose bool `short:"v" long:"verbose" description:"More verbose logging, include debug fields in the scan results"`
}

// Module implements the zgrab2.Module interface.
type Module struct {
}

// Scanner implements the zgrab2.Scanner interface.
type Scanner struct {
	config *Flags
}

// RegisterModule registers the zgrab2 module.
func RegisterModule() {
	var module Module
	_, err := zgrab2.AddCommand("pop3_implicit_tls", "Fetches POP3 capabilities for implicit TLS", module.Description(), 995, &module)
	if err != nil {
		log.Fatal(err)
	}
}

// NewFlags returns a default Flags object.
func (module *Module) NewFlags() interface{} {
	return new(Flags)
}

// NewScanner returns a new Scanner instance.
func (module *Module) NewScanner() zgrab2.Scanner {
	return new(Scanner)
}

// Description returns an overview of this module.
func (module *Module) Description() string {
	return "Fetches for POP3 capabilities for implicit TLS"
}

// Validate checks that the flags are valid.
// On success, returns nil.
// On failure, returns an error instance describing the error.
func (flags *Flags) Validate(args []string) error {
	return nil
}

// Help returns the module's help string.
func (flags *Flags) Help() string {
	return "todo"
}

// Init initializes the Scanner.
func (scanner *Scanner) Init(flags zgrab2.ScanFlags) error {
	f, _ := flags.(*Flags)
	scanner.config = f
	return nil
}

// InitPerSender initializes the scanner for a given sender.
func (scanner *Scanner) InitPerSender(senderID int) error {
	return nil
}

// GetName returns the Scanner name defined in the Flags.
func (scanner *Scanner) GetName() string {
	return scanner.config.Name
}

// GetTrigger returns the Trigger defined in the Flags.
func (scanner *Scanner) GetTrigger() string {
	return scanner.config.Trigger
}

// Protocol returns the protocol identifier of the scan.
func (scanner *Scanner) Protocol() string {
	return "pop3"
}

// Scan performs the IMAP scan.
func (scanner *Scanner) Scan(target zgrab2.ScanTarget) (zgrab2.ScanStatus, interface{}, error) {

	result := &ScanResults{}
	singleReadTimeout := time.Second * 5

	// Step 0
	// Connect to Target
	c, err := target.Open(&scanner.config.BaseFlags)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), nil, err
	}
	defer c.Close()
	conn := Connection{Conn: c}
	result.Status = 0

	var ret string
	var command string

	// Step 1
	// TLS - Handshake
	result.Trace = append(result.Trace, "-- TLS Handshake --")
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	tlsConn, err := scanner.config.TLSFlags.GetTLSConnection(conn.Conn)
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	// Log TLS details if set on verbose
	if scanner.config.Verbose {
		result.TLSLog = tlsConn.GetLog()
	}
	err = tlsConn.Handshake()
	if err != nil {
		return zgrab2.TryGetScanStatus(err), result, err
	}
	conn.Conn = tlsConn
	result.Status++

	// Step 2
	// Read greeting
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	ret, err = conn.ReadResponse()
	result.Greeting = ret
	if err != nil {
		status := zgrab2.TryGetScanStatus(err)
		return status, result, err
	}
	result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
	if !strings.Contains(strings.ToUpper(ret), "+OK") && !strings.Contains(strings.ToUpper(ret), "-ERR") {
		status := zgrab2.ScanStatus("no-pop3")
		return status, result, err
	}
	result.Status++

	// Step 3
	// Send capa-Command
	command = "CAPA"
	result.Trace = append(result.Trace, "C: "+command)
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	ret, err = conn.SendCommandCAPA(command)
	result.Capabilities = ret
	result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
	result.Status++

	// Step 4
	// Send QUIT and close connection
	command = "QUIT"
	result.Trace = append(result.Trace, "C: "+command)
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	ret, err = conn.SendCommand(command)
	if err != nil {
		// Some servers don't properly terminate the last message -> no reason to panic
		if err.Error() != "EOF" {
			return zgrab2.TryGetScanStatus(err), result, err
		}
	}
	result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
	result.Status++

	// Step 5
	// Read possible further responses until close/timeout
	conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	for ret, err = conn.ReadResponse(); err == nil; ret, err = conn.ReadResponse() {
		result.Trace = append(result.Trace, "S: "+strings.Trim(ret, "\r\n"))
		// Such responses are interpreted as a vulnerability
		conn.Conn.SetReadDeadline(time.Now().Add(singleReadTimeout))
	}
	result.Status++

	return zgrab2.SCAN_SUCCESS, result, nil
}
