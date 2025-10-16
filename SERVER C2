package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	
	"strings"
	"sync"
	"time"
)

// Estructuras
type CmdRequest struct {
	ID  string `json:"id"`
	Cmd string `json:"cmd"`
}

type CmdResult struct {
	ID      string `json:"id"`
	Comando string `json:"comando"`
	Salida  string `json:"salida"`
}

type HistoryEntry struct {
	ID       string
	Command  string
	Output   string
	Executed time.Time
}

// Estado compartido
var (
	mu       sync.Mutex
	pending  *CmdRequest
	lastSeen time.Time
	history  []HistoryEntry
)

// Manejador HTTP para GET y POST
func comandoHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		mu.Lock()
		cmd := pending
		mu.Unlock()

		if cmd == nil {
			w.WriteHeader(http.StatusNoContent) // 204 No Content
			return
		}

		log.Printf("📤 [DISPATCH] Comando enviado al cliente: ID=%s Cmd=%s\n", cmd.ID, cmd.Cmd)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cmd)

	case http.MethodPost:
		var res CmdResult
		if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		mu.Lock()
		if pending != nil && pending.ID == res.ID && pending.Cmd == res.Comando {
			pending = nil
		}
		lastSeen = time.Now()
		history = append(history, HistoryEntry{
			ID:       res.ID,
			Command:  res.Comando,
			Output:   res.Salida,
			Executed: lastSeen,
		})
		mu.Unlock()

		// MOSTRAR RESULTADO DE FORMA ACUMULATIVA
		log.Println("═════════════════════════════════════════════════════")
		log.Printf("📥 Resultado recibido [%s]", lastSeen.Format("2006-01-02 15:04:05"))
		log.Printf("🧾 Comando ejecutado: %s", res.Comando)
		log.Println("📄 Salida del cliente:")
		log.Println("-----------------------------------------------------")
		log.Println(res.Salida)
		log.Println("═════════════════════════════════════════════════════\n")

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// Loop para recibir comandos del admin desde consola
func adminInputLoop() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("🛠️  Comando > ")
		if !scanner.Scan() {
			break
		}
		text := strings.TrimSpace(scanner.Text())

		switch text {
		case "":
			continue
		case "exit", "quit":
			fmt.Println("⏹️ Saliendo del servidor...")
			os.Exit(0)
		case "status":
			mu.Lock()
			fmt.Printf("📊 Última conexión cliente: %v\n", lastSeen)
			if pending != nil {
				fmt.Printf("⌛ Comando pendiente: ID=%s Cmd=%s\n", pending.ID, pending.Cmd)
			} else {
				fmt.Println("✅ No hay comandos pendientes.")
			}
			mu.Unlock()
		case "history":
			mu.Lock()
			if len(history) == 0 {
				fmt.Println("📚 No hay comandos ejecutados aún.")
			} else {
				fmt.Println("📚 Historial de comandos ejecutados:")
				for i, entry := range history {
					fmt.Printf("%d) [%s] ID=%s Cmd=%s\n", i+1, entry.Executed.Format("15:04:05"), entry.ID, entry.Command)
				}
			}
			mu.Unlock()
		default:
			mu.Lock()
			if pending != nil {
				fmt.Printf("⚠️ Ya hay un comando pendiente: ID=%s Cmd=%s. Espera a que el cliente responda.\n", pending.ID, pending.Cmd)
			} else {
				// Generar ID único simple con timestamp
				id := fmt.Sprintf("%d", time.Now().UnixNano())
				pending = &CmdRequest{ID: id, Cmd: text}
				lastSeen = time.Now()
				log.Printf("🆕 [ADMIN] Comando seteado: ID=%s Cmd=%s", id, text)
			}
			mu.Unlock()
		}
	}
}

func main() {
	http.HandleFunc("/", comandoHandler)
	http.HandleFunc("/comando", comandoHandler)

	fmt.Println("🔐 Servidor HTTPS escuchando en https://127.0.0.1:8080/")
	fmt.Println("⌨️  Escribe comandos en esta terminal para enviarlos al cliente...")
	fmt.Println("   Comandos especiales:")
	fmt.Println("     status  -> Ver estado actual")
	fmt.Println("     history -> Ver historial de resultados")
	fmt.Println("     exit    -> Salir del servidor\n")

	// Lanzar input admin en goroutine para no bloquear servidor HTTP
	go adminInputLoop()

	// Iniciar servidor TLS (asegúrate de tener cert.pem y key.pem)
	err := http.ListenAndServeTLS("127.0.0.1:8080", "cert.pem", "key.pem", nil)
	if err != nil {
		log.Fatalf("❌ Error al iniciar servidor: %v", err)
	}
}
