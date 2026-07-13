package auth

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
)

func TestTerminalPrompterDefaultSaveAndExactPrompt(t *testing.T) {
	var output bytes.Buffer
	prompt := NewTerminalPrompter(bufio.NewReader(strings.NewReader("\n")), &output)
	save, err := prompt.ConfirmSave()
	if err != nil || !save {
		t.Fatalf("got save=%v err=%v", save, err)
	}
	if output.String() != "Save credentials in the OS keyring? [Y/n] " {
		t.Fatalf("unexpected prompt %q", output.String())
	}
}

func TestTerminalPrompterReadsEmail(t *testing.T) {
	var output bytes.Buffer
	prompt := NewTerminalPrompter(bufio.NewReader(strings.NewReader(" person@example.test \n")), &output)
	email, err := prompt.Email()
	if err != nil || email != "person@example.test" {
		t.Fatalf("got %q, %v", email, err)
	}
	if output.String() != "Email: " {
		t.Fatalf("unexpected prompt %q", output.String())
	}
}
