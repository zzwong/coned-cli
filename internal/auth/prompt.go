package auth

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Prompter makes credential prompts testable without a terminal.
type Prompter interface {
	Email() (string, error)
	MFACode() (string, error)
	ConfirmSave() (bool, error)
}

// PasswordTerminal abstracts terminal detection and password entry.
type PasswordTerminal interface {
	IsTerminal(io.Reader) bool
	ReadPassword(io.Reader) ([]byte, error)
}

// TerminalPrompter reads ordinary interactive answers from input.
type TerminalPrompter struct {
	input *bufio.Reader
	out   io.Writer
}

// NewTerminalPrompter returns a terminal prompter using the supplied streams.
func NewTerminalPrompter(input *bufio.Reader, out io.Writer) TerminalPrompter {
	return TerminalPrompter{input: input, out: out}
}

func (p TerminalPrompter) Email() (string, error) {
	if _, err := fmt.Fprint(p.out, "Email: "); err != nil {
		return "", err
	}
	value, err := p.input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read email: %w", err)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrInvalidCredentials
	}
	return value, nil
}

func (p TerminalPrompter) MFACode() (string, error) {
	if _, err := fmt.Fprint(p.out, "Verification code (or type resend): "); err != nil {
		return "", err
	}
	value, err := p.input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read verification code: %w", err)
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrInvalidCredentials
	}
	return value, nil
}

func (p TerminalPrompter) ConfirmSave() (bool, error) {
	if _, err := fmt.Fprint(p.out, "Save credentials in the OS keyring? [Y/n] "); err != nil {
		return false, err
	}
	value, err := p.input.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, fmt.Errorf("read save confirmation: %w", err)
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid save confirmation")
	}
}

// SystemPasswordTerminal reads hidden passwords from an operating-system terminal.
type SystemPasswordTerminal struct{}

func (SystemPasswordTerminal) IsTerminal(input io.Reader) bool {
	file, ok := input.(*os.File)
	return ok && term.IsTerminal(int(file.Fd()))
}

func (SystemPasswordTerminal) ReadPassword(input io.Reader) ([]byte, error) {
	file, ok := input.(*os.File)
	if !ok {
		return nil, fmt.Errorf("password input is not a terminal")
	}
	return term.ReadPassword(int(file.Fd()))
}
