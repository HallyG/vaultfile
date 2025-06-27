package passwordutil_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/HallyG/vaultfile/internal/passwordutil"
	"github.com/stretchr/testify/require"
)

var _ passwordutil.PasswordReader = (*MockTerminal)(nil)

type MockTerminal struct {
	inputs     [][]byte
	prompts    []string
	readErrors []error
	isTerminal bool
}

func (m *MockTerminal) IsTerminal() bool {
	return m.isTerminal
}

func (m *MockTerminal) ReadPassword(prompt string, output io.Writer) ([]byte, error) {
	m.prompts = append(m.prompts, prompt)

	if len(m.readErrors) > 0 {
		err := m.readErrors[0]
		m.readErrors = m.readErrors[1:]

		if err != nil {
			return nil, err
		}
	}

	if len(m.inputs) == 0 {
		return nil, errors.New("no more inputs available")
	}

	password := m.inputs[0]
	m.inputs = m.inputs[1:]

	if _, err := fmt.Fprintln(output); err != nil {
		return nil, err
	}

	return password, nil
}

func TestPromptPassword(t *testing.T) {
	t.Run("password input with no confirmation", func(t *testing.T) {
		t.Parallel()

		output := &bytes.Buffer{}
		reader := &MockTerminal{
			inputs: [][]byte{
				[]byte("testpassword"),
			},
			isTerminal: true,
		}

		password, err := passwordutil.PromptPassword(reader, output, false)
		require.NoError(t, err)

		expectedPassword := []byte("testpassword")
		require.Equal(t, expectedPassword, password)
		require.Equal(t, []string{"Enter password: "}, reader.prompts)
	})

	t.Run("confirmation password mismatch", func(t *testing.T) {
		t.Parallel()

		output := &bytes.Buffer{}
		reader := &MockTerminal{
			inputs: [][]byte{
				[]byte("testpassword"),
				[]byte("wrongpassword"),
			},
			isTerminal: true,
		}

		password, err := passwordutil.PromptPassword(reader, output, true)
		require.ErrorContains(t, err, "passwords do not match")
		require.Empty(t, password)
		require.Equal(t, []string{"Enter password: ", "Confirm password: "}, reader.prompts)
	})

	t.Run("confirmation password match", func(t *testing.T) {
		t.Parallel()

		output := &bytes.Buffer{}
		reader := &MockTerminal{
			inputs: [][]byte{
				[]byte("testpassword"),
				[]byte("testpassword"),
			},
			isTerminal: true,
		}

		password, err := passwordutil.PromptPassword(reader, output, true)
		require.NoError(t, err)
		require.Equal(t, []byte("testpassword"), password)
		require.Equal(t, []string{"Enter password: ", "Confirm password: "}, reader.prompts)
	})

	t.Run("error reading password", func(t *testing.T) {
		t.Parallel()

		output := &bytes.Buffer{}
		reader := &MockTerminal{
			inputs: [][]byte{
				[]byte("testpassword"),
				[]byte("testpassword"),
			},
			readErrors: []error{errors.New("mock error")},
			isTerminal: true,
		}

		password, err := passwordutil.PromptPassword(reader, output, true)
		require.Error(t, err)
		require.Empty(t, password)
		require.Equal(t, []string{"Enter password: "}, reader.prompts)
	})

	t.Run("error reading confirmation password", func(t *testing.T) {
		t.Parallel()

		output := &bytes.Buffer{}
		reader := &MockTerminal{
			inputs: [][]byte{
				[]byte("testpassword"),
				[]byte("testpassword"),
			},
			readErrors: []error{nil, errors.New("mock error")},
			isTerminal: true,
		}

		password, err := passwordutil.PromptPassword(reader, output, true)
		require.Error(t, err)
		require.Empty(t, password)
		require.Equal(t, []string{"Enter password: ", "Confirm password: "}, reader.prompts)
	})

	t.Run("error when non at terminal", func(t *testing.T) {
		t.Parallel()

		output := &bytes.Buffer{}
		reader := &MockTerminal{
			inputs:     [][]byte{[]byte("testpassword")},
			isTerminal: false,
		}

		password, err := passwordutil.PromptPassword(reader, output, false)
		require.Error(t, err)
		require.Empty(t, password)
		require.Nil(t, reader.prompts)
	})

	t.Run("error when empty password input", func(t *testing.T) {
		t.Parallel()

		output := &bytes.Buffer{}
		reader := &MockTerminal{
			inputs:     [][]byte{[]byte("")},
			isTerminal: true,
		}

		password, err := passwordutil.PromptPassword(reader, output, false)
		require.Error(t, err)
		require.Empty(t, password)
		require.Contains(t, err.Error(), "password cannot be empty")
	})

	t.Run("nil output writer", func(t *testing.T) {
		t.Parallel()

		reader := &MockTerminal{
			isTerminal: true,
		}

		password, err := passwordutil.PromptPassword(reader, nil, false)
		require.Error(t, err)
		require.Empty(t, password)
		require.Contains(t, err.Error(), "output writer cannot be nil")
	})
}

func TestZeroPassword(t *testing.T) {
	t.Run("zero out password", func(t *testing.T) {
		t.Parallel()

		password := []byte("sensitivepassword")
		passwordutil.ZeroPassword(password)

		expected := make([]byte, len(password))
		require.Equal(t, expected, password)
	})
}
