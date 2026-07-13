package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/zzwong/coned-cli/internal/auth"
	"github.com/zzwong/coned-cli/internal/coned"
	"github.com/zzwong/coned-cli/internal/securestore"
)

func newAuthCommand(options *Options, deps Dependencies, input *bufio.Reader, rawInput io.Reader) *cobra.Command {
	authCmd := &cobra.Command{Use: "auth", Short: "Manage authentication", Args: cobra.NoArgs}
	for _, isInit := range []bool{false, true} {
		use := "login"
		if isInit {
			use = "init"
		}
		var force, noStore, passwordStdin bool
		command := &cobra.Command{Use: use, Short: "Authenticate with Con Edison", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
			return authenticate(cmd, options.Profile, options.Timeout, deps, input, rawInput, force, noStore, passwordStdin)
		}}
		command.Flags().BoolVar(&force, "force", false, "ignore any stored session")
		command.Flags().BoolVar(&noStore, "no-store", false, "do not persist newly obtained authentication")
		command.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read one newline-terminated password from standard input")
		authCmd.AddCommand(command)
	}
	authCmd.AddCommand(&cobra.Command{Use: "status", Short: "Show authentication status", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return authStatus(cmd, options.Profile, options.JSON, deps)
	}})
	var browserEndpoint string
	importBrowser := &cobra.Command{Use: "import-browser", Short: "Import an authenticated session from local Chromium", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), options.Timeout)
		defer cancel()
		session, err := coned.ImportBrowserSession(ctx, browserEndpoint)
		if err != nil {
			return err
		}
		if validator, ok := deps.Authenticator.(interface {
			ValidateAuthenticatedSession(context.Context, auth.Session) error
		}); ok {
			if err := validator.ValidateAuthenticatedSession(ctx, session); err != nil {
				return safeAuthenticationError(err)
			}
		}
		if err := auth.SaveSession(deps.Store, options.Profile, session); err != nil {
			return auth.ErrStorageFailed
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), "authenticated session imported")
		return err
	}}
	importBrowser.Flags().StringVar(&browserEndpoint, "endpoint", "", "CDP HTTP or WebSocket endpoint (auto-discovered by default)")
	authCmd.AddCommand(importBrowser)
	var forget bool
	logout := &cobra.Command{Use: "logout", Short: "Delete the stored session", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		return authLogout(cmd, options.Profile, options.Timeout, deps, forget)
	}}
	logout.Flags().BoolVar(&forget, "forget", false, "also delete stored credentials")
	authCmd.AddCommand(logout)
	return authCmd
}

func authenticate(cmd *cobra.Command, profile string, timeout time.Duration, deps Dependencies, input *bufio.Reader, rawInput io.Reader, force, noStore, passwordStdin bool) error {
	storedSession, sessionErr := auth.LoadSession(deps.Store, profile)
	if sessionErr == nil {
		if restorer, ok := deps.Authenticator.(auth.SessionRestorer); ok {
			restore := storedSession
			if force {
				restore.Cookies = nil
				for _, cookie := range storedSession.Cookies {
					if cookie.Name == "CE_DEVICE_ID" {
						restore.Cookies = append(restore.Cookies, cookie)
					}
				}
			}
			_ = restorer.RestoreSession(restore)
		}
		if !force && storedSession.State(deps.Clock()) == auth.SessionValid {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "authenticated")
			return err
		}
	} else if !errors.Is(sessionErr, securestore.ErrNotFound) && !errors.Is(sessionErr, auth.ErrInvalidSession) {
		return auth.ErrStorageFailed
	}
	prompted := false
	credentials, err := auth.LoadCredentials(deps.Store, profile)
	if err != nil && !errors.Is(err, securestore.ErrNotFound) && !errors.Is(err, auth.ErrInvalidCredentials) {
		return auth.ErrStorageFailed
	}
	if auth.ValidateCredentials(credentials) != nil {
		prompted = true
		var err error
		if !passwordStdin && !deps.PasswordTerminal.IsTerminal(rawInput) {
			return auth.ErrPasswordInputNotTerminal
		}
		credentials.Email, err = deps.Prompter.Email()
		if err != nil {
			return auth.ErrPromptFailed
		}
		if passwordStdin {
			credentials.Password, err = readPasswordStdin(input)
		} else {
			if !deps.PasswordTerminal.IsTerminal(rawInput) {
				return auth.ErrPasswordInputNotTerminal
			}
			if _, err = fmt.Fprint(cmd.OutOrStdout(), "Password: "); err != nil {
				return auth.ErrPromptFailed
			}
			var password []byte
			password, err = deps.PasswordTerminal.ReadPassword(rawInput)
			if _, outputErr := fmt.Fprintln(cmd.OutOrStdout()); err == nil {
				err = outputErr
			}
			credentials.Password = string(password)
		}
		if err != nil {
			if errors.Is(err, auth.ErrInvalidPasswordStdin) || errors.Is(err, auth.ErrInvalidCredentials) {
				return err
			}
			return auth.ErrPasswordReadFailed
		}
	}
	if err := auth.ValidateCredentials(credentials); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
	session, err := deps.Authenticator.Authenticate(ctx, credentials)
	cancel()
	if errors.Is(err, coned.ErrMFARequired) {
		verifier, ok := deps.Authenticator.(auth.MFAAuthenticator)
		if !ok {
			return coned.ErrMFARequired
		}
		if _, outputErr := fmt.Fprintln(cmd.OutOrStdout(), "Verification required. Con Edison may enforce a 3-minute resend cooldown."); outputErr != nil {
			return outputErr
		}
		for {
			code, promptErr := deps.Prompter.MFACode()
			if promptErr != nil {
				return auth.ErrPromptFailed
			}
			if strings.EqualFold(strings.TrimSpace(code), "resend") {
				resender, ok := deps.Authenticator.(auth.MFAResender)
				if !ok {
					return coned.ErrChallengeRequired
				}
				requestCtx, requestCancel := context.WithTimeout(cmd.Context(), timeout)
				resendErr := resender.ResendMFA(requestCtx)
				requestCancel()
				if resendErr != nil {
					return safeAuthenticationError(resendErr)
				}
				if _, outputErr := fmt.Fprintln(cmd.OutOrStdout(), "Verification code requested."); outputErr != nil {
					return outputErr
				}
				continue
			}
			verifyCtx, verifyCancel := context.WithTimeout(cmd.Context(), timeout)
			session, err = verifier.VerifyMFA(verifyCtx, code)
			verifyCancel()
			break
		}
	}
	if err != nil {
		return safeAuthenticationError(err)
	}
	if err := auth.ValidateSession(session); err != nil {
		return err
	}
	if len(session.OpowerEntities) == 0 {
		session.OpowerEntities = append([]string(nil), storedSession.OpowerEntities...)
	}
	present := map[string]bool{}
	for _, cookie := range session.Cookies {
		present[cookie.Name] = true
	}
	for _, cookie := range storedSession.Cookies {
		if !present[cookie.Name] && (cookie.Name == "CE_DEVICE_ID" || cookie.Name == "CE_ACCOUNT_FOCUS") {
			session.Cookies = append(session.Cookies, cookie)
		}
	}
	if session.AuthenticatedAt.IsZero() {
		session.AuthenticatedAt = deps.Clock()
	}
	if !noStore {
		if err := auth.SaveSession(deps.Store, profile, session); err != nil {
			return auth.ErrStorageFailed
		}
		if prompted {
			save, err := deps.Prompter.ConfirmSave()
			if err != nil {
				return auth.ErrPromptFailed
			}
			if save {
				if err := auth.SaveCredentials(deps.Store, profile, credentials); err != nil {
					return auth.ErrStorageFailed
				}
			}
		}
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), "authenticated")
	return err
}

func safeAuthenticationError(err error) error {
	if protocol, ok := coned.AsSafeProtocolError(err); ok {
		return protocol
	}
	for _, safe := range []error{auth.ErrInvalidCredentials, auth.ErrInvalidSession, auth.ErrAuthenticationFailed, auth.ErrNotImplemented, auth.ErrPasswordInputNotTerminal, auth.ErrInvalidPasswordStdin, auth.ErrPasswordReadFailed, coned.ErrInvalidCredentials, coned.ErrMFARequired, coned.ErrChallengeRequired, coned.ErrSessionExpired, coned.ErrProtocolChanged} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	return auth.ErrAuthenticationFailed
}

// readPasswordStdin consumes exactly one newline-terminated line from input.
func readPasswordStdin(input *bufio.Reader) (string, error) {
	line, err := input.ReadString('\n')
	if err != nil {
		return "", auth.ErrInvalidPasswordStdin
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if line == "" {
		return "", auth.ErrInvalidCredentials
	}
	return line, nil
}

func statusName(state auth.SessionState) string {
	switch state {
	case auth.SessionValid:
		return "authenticated"
	case auth.SessionExpired:
		return "expired"
	default:
		return "not authenticated"
	}
}

func authStatus(cmd *cobra.Command, profile string, jsonOutput bool, deps Dependencies) error {
	session, err := auth.LoadSession(deps.Store, profile)
	state := auth.SessionInvalid
	if err == nil {
		state = session.State(deps.Clock())
	} else if !errors.Is(err, securestore.ErrNotFound) && !errors.Is(err, auth.ErrInvalidSession) {
		return auth.ErrStorageFailed
	}
	if jsonOutput {
		result := struct {
			Profile                 string     `json:"profile"`
			Status                  string     `json:"status"`
			AuthenticationTimestamp *time.Time `json:"authentication_timestamp,omitempty"`
		}{Profile: profile, Status: statusName(state)}
		if !session.AuthenticatedAt.IsZero() {
			result.AuthenticationTimestamp = &session.AuthenticatedAt
		}
		data, err := json.Marshal(result)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return err
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), statusName(state))
	return err
}

func authLogout(cmd *cobra.Command, profile string, timeout time.Duration, deps Dependencies, forget bool) error {
	session, loadErr := auth.LoadSession(deps.Store, profile)
	var errorsFound []error
	if loadErr == nil {
		ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
		err := deps.Authenticator.Logout(ctx, session)
		cancel()
		if err != nil {
			errorsFound = append(errorsFound, auth.ErrLogoutFailed)
		}
	} else if !errors.Is(loadErr, securestore.ErrNotFound) {
		errorsFound = append(errorsFound, auth.ErrStorageFailed)
	}
	if err := auth.DeleteSession(deps.Store, profile); err != nil && !errors.Is(err, securestore.ErrNotFound) {
		errorsFound = append(errorsFound, auth.ErrStorageFailed)
	}
	if forget {
		if err := auth.DeleteCredentials(deps.Store, profile); err != nil && !errors.Is(err, securestore.ErrNotFound) {
			errorsFound = append(errorsFound, auth.ErrStorageFailed)
		}
	}
	if len(errorsFound) > 0 {
		return errors.Join(errorsFound...)
	}
	_, err := fmt.Fprintln(cmd.OutOrStdout(), "not authenticated")
	return err
}
