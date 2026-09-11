package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/chzyer/readline"
)

// DynamicCompleter provides tab-completion based on authentication state
type DynamicCompleter struct {
	state *CLIState
}

// Do implements readline.AutoCompleter
func (d *DynamicCompleter) Do(line []rune, pos int) ([][]rune, int) {
	prefix := strings.ToLower(string(line[:pos]))

	var commands []string
	if !d.state.Authenticated {
		commands = []string{"register", "login", "help", "exit"}
	} else {
		commands = []string{"whoami", "enable-2fa", "disable-2fa", "logout", "help", "exit"}
	}

	var suggestions [][]rune
	for _, cmd := range commands {
		if strings.HasPrefix(cmd, prefix) {
			suffix := cmd[len(prefix):]
			suggestions = append(suggestions, []rune(suffix))
		}
	}

	return suggestions, len(prefix)
}

// RunREPL starts the interactive command-line loop
func RunREPL(client *APIClient) {
	state := &CLIState{
		Authenticated: false,
	}

	completer := &DynamicCompleter{state: state}

	// Try initializing readline with tab-completion and history
	rl, err := readline.NewEx(&readline.Config{
		Prompt:          "auth-cli> ",
		AutoComplete:    completer,
		HistoryFile:     "/tmp/.auth_cli_history",
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	})

	if err != nil {
		// Fallback to simple scanner if readline fails (e.g. non-tty environments)
		runFallbackScanner(client, state)
		return
	}
	defer rl.Close()

	fmt.Println()
	fmt.Printf("%s=====================================================%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Printf("%s      Secure CLI Login System with 2FA (TOTP)        %s\n", ColorBold, ColorReset)
	fmt.Printf("%s=====================================================%s\n", ColorBold+ColorCyan, ColorReset)
	fmt.Println("Type 'help' to view available commands or 'exit' to quit.")
	fmt.Println("Press <Tab> for command completion.")
	fmt.Println()

	for {
		// Update prompt dynamically based on authentication state
		if state.Authenticated {
			rl.SetPrompt(fmt.Sprintf("%sauth-cli (%s%s%s)%s> ", ColorCyan, ColorGreen, state.Username, ColorCyan, ColorReset))
		} else {
			rl.SetPrompt(fmt.Sprintf("%sauth-cli%s> ", ColorCyan, ColorReset))
		}

		line, err := rl.Readline()
		if err != nil { // io.EOF or readline.ErrInterrupt
			if err == io.EOF || err == readline.ErrInterrupt {
				fmt.Println("\nExiting. Goodbye!")
				break
			}
			PrintError("Readline error: %v", err)
			continue
		}

		cmd := strings.TrimSpace(strings.ToLower(line))
		if cmd == "" {
			continue
		}

		executeCommand(cmd, client, state)
		if cmd == "exit" {
			break
		}
	}
}

func executeCommand(cmd string, client *APIClient, state *CLIState) {
	if !state.Authenticated {
		switch cmd {
		case "register":
			HandleRegister(client)
		case "login":
			HandleLogin(client, state)
		case "help":
			PrintHelp(false)
		case "exit":
			fmt.Println("Exiting. Goodbye!")
			os.Exit(0)
		default:
			PrintError("Unknown command '%s'. Type 'help' for available commands.", cmd)
		}
	} else {
		switch cmd {
		case "whoami":
			HandleWhoAmI(client)
		case "enable-2fa":
			HandleEnable2FA(client)
		case "disable-2fa":
			HandleDisable2FA(client)
		case "logout":
			HandleLogout(client, state)
		case "help":
			PrintHelp(true)
		case "exit":
			fmt.Println("Exiting. Goodbye!")
			os.Exit(0)
		default:
			PrintError("Unknown command '%s'. Type 'help' for available commands.", cmd)
		}
	}
}

// Fallback scanner for non-interactive / headless execution
func runFallbackScanner(client *APIClient, state *CLIState) {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		if state.Authenticated {
			fmt.Printf("auth-cli (%s)> ", state.Username)
		} else {
			fmt.Print("auth-cli> ")
		}

		if !scanner.Scan() {
			break
		}

		cmd := strings.TrimSpace(strings.ToLower(scanner.Text()))
		if cmd == "" {
			continue
		}

		executeCommand(cmd, client, state)
		if cmd == "exit" {
			break
		}
	}
}
