// cordova/admin/cli/key.go

package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	. "cordova/core/ipc"
)

var keyCmd = &cobra.Command{
	Use:   "key",
	Short: "Key management",
}

func init() {
	keyCmd.AddCommand(keyGetCmd)
	keyCmd.AddCommand(keyAddCmd)
	keyCmd.AddCommand(keyRotateCmd)
	keyCmd.AddCommand(keyDeleteCmd)
	keyCmd.AddCommand(keyListCmd)
}

var keyGetCmd = &cobra.Command{
	Use:   "get <name>",
	Short: "Print a key value",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := Client.Send(CmdKeyGet, KeyGetParams{Name: args[0]})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		var d KeyGetData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return err
		}
		fmt.Println(d.Value)
		return nil
	},
}

var keyAddCmd = &cobra.Command{
	Use:   "add <name>",
	Short: "Add a new key (value prompted, hidden)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		_, _ = fmt.Fprintf(os.Stderr, "value: ")
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("reading value: %w", err)
		}
		if len(value) == 0 {
			return fmt.Errorf("value cannot be empty")
		}

		resp, err := Client.Send(CmdKeySet, KeySetParams{Name: name, Value: string(value)})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Printf("added %s\n", name)
		return nil
	},
}
var keyRotateCmd = &cobra.Command{
	Use:   "rotate <name>",
	Short: "Replace a key value (new value prompted, hidden)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		_, _ = fmt.Fprintf(os.Stderr, "new value: ")
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		_, _ = fmt.Fprintln(os.Stderr)
		if err != nil {
			return fmt.Errorf("reading value: %w", err)
		}
		if len(value) == 0 {
			return fmt.Errorf("value cannot be empty")
		}

		resp, err := Client.Send(CmdKeySet, KeySetParams{Name: name, Value: string(value)})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Printf("rotated %s\n", name)
		return nil
	},
}
var keyDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a key (prompts for confirmation)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := args[0]
		fmt.Printf("delete %q? [y/N]: ", name)
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if strings.ToLower(strings.TrimSpace(scanner.Text())) != "y" {
			fmt.Println("aborted")
			return nil
		}

		resp, err := Client.Send(CmdKeyDelete, KeyDeleteParams{Name: name})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Printf("deleted %s\n", name)
		return nil
	},
}
var keyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all key names",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := Client.Send(CmdKeyList, nil)
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		var d KeyListData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return err
		}
		if len(d.Keys) == 0 {
			fmt.Println("no keys")
			return nil
		}
		for _, k := range d.Keys {
			fmt.Println(k)
		}
		return nil
	},
}
