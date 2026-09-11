package cli

import (
	"fmt"
	"strings"
)

// CLIState tracks the client authentication state
type CLIState struct {
	Authenticated bool
	Username      string
}

// HandleRegister handles the user registration flow
func HandleRegister(client *APIClient) {
	PrintInfo("Initiating user registration...")

	username, err := ReadLine("Enter desired username: ")
	if err != nil || username == "" {
		PrintError("Username cannot be empty")
		return
	}

	password, err := ReadPassword("Enter password (min 8 chars): ")
	if err != nil || password == "" {
		PrintError("Password cannot be empty")
		return
	}

	confirmPassword, err := ReadPassword("Confirm password: ")
	if err != nil || confirmPassword == "" {
		PrintError("Password confirmation cannot be empty")
		return
	}

	if password != confirmPassword {
		PrintError("Passwords do not match. Registration aborted.")
		return
	}

	err = client.Register(username, password)
	if err != nil {
		PrintError("%v", err)
		return
	}

	PrintSuccess("Registration successful for user '%s'! You may now log in.", username)
}

// HandleLogin handles the user login flow, prompting for 2FA if enabled
func HandleLogin(client *APIClient, state *CLIState) {
	username, err := ReadLine("Username: ")
	if err != nil || username == "" {
		PrintError("Username is required")
		return
	}

	password, err := ReadPassword("Password: ")
	if err != nil || password == "" {
		PrintError("Password is required")
		return
	}

	// First login attempt without TOTP to verify password or check if 2FA is required
	res, err := client.Login(username, password, "")
	if err != nil {
		PrintError("%v", err)
		return
	}

	if res.Status == "mfa_required" {
		PrintWarning("Two-factor authentication is enabled for this account.")
		totpCode, err := ReadLine("Enter 6-digit Authenticator code: ")
		if err != nil || totpCode == "" {
			PrintError("2FA verification code is required")
			return
		}

		res, err = client.Login(username, password, totpCode)
		if err != nil {
			PrintError("%v", err)
			return
		}
	}

	if res.Status == "success" {
		state.Authenticated = true
		state.Username = res.User.Username

		PrintSuccess("Authentication successful! Welcome back, %s.", state.Username)
		// Requirement 5: User Details (Auto-display After Login)
		DisplayUserDetails(&res.User)
	}
}

// HandleWhoAmI retrieves and displays the current user profile
func HandleWhoAmI(client *APIClient) {
	user, err := client.WhoAmI()
	if err != nil {
		PrintError("%v", err)
		return
	}

	DisplayUserDetails(user)
}

// HandleEnable2FA initiates and completes TOTP MFA enrollment
func HandleEnable2FA(client *APIClient) {
	PrintInfo("Setting up Two-Factor Authentication (TOTP)...")

	res, err := client.GenerateMFA()
	if err != nil {
		PrintError("%v", err)
		return
	}

	DisplayMFASetup(res.Secret, res.URI)

	code, err := ReadLine("Enter the 6-digit code from Google Authenticator to confirm: ")
	if err != nil || code == "" {
		PrintError("Verification code cannot be empty")
		return
	}

	if err := client.EnableMFA(code); err != nil {
		PrintError("%v", err)
		return
	}

	PrintSuccess("2FA has been successfully ENABLED for your account!")
}

// HandleDisable2FA deactivates 2FA
func HandleDisable2FA(client *APIClient) {
	confirm, err := ReadLine("Are you sure you want to disable 2FA? (yes/no): ")
	if err != nil || !strings.EqualFold(strings.TrimSpace(confirm), "yes") {
		PrintInfo("Operation cancelled.")
		return
	}

	if err := client.DisableMFA(); err != nil {
		PrintError("%v", err)
		return
	}

	PrintSuccess("2FA has been DISABLED for your account.")
}

// HandleLogout terminates the active session
func HandleLogout(client *APIClient, state *CLIState) {
	if err := client.Logout(); err != nil {
		PrintError("%v", err)
		return
	}

	state.Authenticated = false
	state.Username = ""
	PrintSuccess("Session terminated. You have been logged out.")
}

// PrintHelp prints the list of commands available in the current mode
func PrintHelp(authenticated bool) {
	fmt.Println()
	fmt.Printf("%sAvailable Commands:%s\n", ColorBold, ColorReset)
	if !authenticated {
		fmt.Printf("  %sregister%s    - Create a new user account\n", ColorCyan, ColorReset)
		fmt.Printf("  %slogin%s       - Login with username and password (+ 2FA if enabled)\n", ColorCyan, ColorReset)
		fmt.Printf("  %shelp%s        - Show this help message\n", ColorCyan, ColorReset)
		fmt.Printf("  %sexit%s        - Exit the application\n", ColorCyan, ColorReset)
	} else {
		fmt.Printf("  %swhoami%s      - Display current user profile and session details\n", ColorCyan, ColorReset)
		fmt.Printf("  %senable-2fa%s  - Enable TOTP-based Two-Factor Authentication\n", ColorCyan, ColorReset)
		fmt.Printf("  %sdisable-2fa%s - Disable Two-Factor Authentication\n", ColorCyan, ColorReset)
		fmt.Printf("  %slogout%s      - Log out and invalidate current session\n", ColorCyan, ColorReset)
		fmt.Printf("  %shelp%s        - Show this help message\n", ColorCyan, ColorReset)
		fmt.Printf("  %sexit%s        - Exit the application\n", ColorCyan, ColorReset)
	}
	fmt.Println()
}
