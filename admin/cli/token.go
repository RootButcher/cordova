// cordova/admin/cli/token.go

package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"cordova/core/ipc"
)

var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Token management",
}

func init() {
	tokenCmd.AddCommand(tokenCreateCmd)
	tokenCmd.AddCommand(tokenListCmd)
	tokenCmd.AddCommand(tokenRevokeCmd)
	tokenCmd.AddCommand(tokenRevokeAllCmd)
}

var (
	nameFlag      string
	tokenUserFlag string
	ephemeralFlag bool
	ttlFlag       string
)

var tokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new token for a user (--user required)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ephemeralFlag && ttlFlag != "" {
			return fmt.Errorf("--ephemeral and --ttl are mutually exclusive")
		}
		if nameFlag == "" {
			return fmt.Errorf("--name is required")
		}
		if tokenUserFlag == "" {
			return fmt.Errorf("--user is required")
		}

		scanner := bufio.NewScanner(os.Stdin)

		fmt.Print("description: ")
		scanner.Scan()
		description := strings.TrimSpace(scanner.Text())
		if description == "" {
			return fmt.Errorf("description is required")
		}

		expiresAt := "" // empty = persistent
		if ephemeralFlag {
			expiresAt = "ephemeral"
		} else if ttlFlag != "" {
			d, err := time.ParseDuration(ttlFlag)
			if err != nil {
				return fmt.Errorf("invalid --ttl %q: %w", ttlFlag, err)
			}
			if d <= 0 {
				return fmt.Errorf("--ttl must be a positive duration")
			}
			expiresAt = time.Now().UTC().Add(d).Format(time.RFC3339)
		}

		params := ipc.TokenAddParams{
			Username:    tokenUserFlag,
			Name:        nameFlag,
			Description: description,
			ExpiresAt:   expiresAt,
		}

		resp, err := Client.Send(ipc.CmdTokenAdd, params)
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}

		var d ipc.TokenAddData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return err
		}

		fmt.Printf("user:    %s\n", d.Username)
		fmt.Printf("name:    %s\n", d.Name)
		fmt.Printf("secret:  %s\n", d.Secret)
		if d.ExpiresAt != "" {
			fmt.Printf("expires: %s\n", d.ExpiresAt)
		}
		fmt.Println("copy the secret now — it will not be shown again")
		return nil
	},
}

func init() {
	tokenCreateCmd.Flags().StringVar(&nameFlag, "name", "", "unique slug name for the token (required)")
	tokenCreateCmd.Flags().StringVar(&tokenUserFlag, "user", "", "username to create the token under (required)")
	tokenCreateCmd.Flags().BoolVar(&ephemeralFlag, "ephemeral", false, "process-scoped token, never written to disk")
	tokenCreateCmd.Flags().StringVar(&ttlFlag, "ttl", "", "time-to-live, e.g. 24h or 30m")
}

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tokens across all users",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := Client.Send(ipc.CmdTokenList, nil)
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		var d ipc.TokenListData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return err
		}
		if len(d.Tokens) == 0 {
			fmt.Println("no tokens")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "USER\tNAME\tDESCRIPTION\tEXPIRES\tCREATED\tLAST USED")
		for _, t := range d.Tokens {
			lastUsed := "never"
			if t.LastUsed != "" {
				if ts, err := time.Parse(time.RFC3339, t.LastUsed); err == nil {
					lastUsed = ts.Format("2006-01-02 15:04")
				}
			}
			created := ""
			if ts, err := time.Parse(time.RFC3339, t.CreatedAt); err == nil {
				created = ts.Format("2006-01-02")
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				t.Username, t.Name, t.Description, t.ExpiresAt, created, lastUsed)
		}
		_ = w.Flush()
		return nil
	},
}

// tokenRevokeCmd removes a single token by its username and name.
var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke --user <username> <name>",
	Short: "Revoke a token by user and name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetString("user")
		if user == "" {
			return fmt.Errorf("--user is required")
		}
		resp, err := Client.Send(ipc.CmdTokenRevoke, ipc.TokenRevokeParams{
			Username: user,
			Name:     args[0],
		})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Printf("revoked %s/%s\n", user, args[0])
		return nil
	},
}

func init() {
	tokenRevokeCmd.Flags().String("user", "", "username that owns the token (required)")
}

// tokenRevokeAllCmd removes every token (optionally for a specific user).
var tokenRevokeAllCmd = &cobra.Command{
	Use:   "revoke-all",
	Short: "Revoke all tokens (type YES to confirm; --user to target one user)",
	RunE: func(cmd *cobra.Command, args []string) error {
		user, _ := cmd.Flags().GetString("user")

		if user != "" {
			fmt.Printf("type YES to revoke all tokens for user %q: ", user)
		} else {
			fmt.Print("type YES to revoke ALL tokens for ALL users: ")
		}

		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if strings.TrimSpace(scanner.Text()) != "YES" {
			fmt.Println("aborted")
			return nil
		}

		resp, err := Client.Send(ipc.CmdTokenRevokeAll, ipc.TokenRevokeAllParams{Username: user})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Println("tokens revoked")
		return nil
	},
}

func init() {
	tokenRevokeAllCmd.Flags().String("user", "", "limit revocation to one user (optional)")
}

// splitTrim splits s on sep, trims whitespace from each part, and drops empty
// entries. Used to parse comma-separated CLI inputs.
func splitTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}