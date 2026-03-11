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
	adminFlag     bool
	ephemeralFlag bool
	ttlFlag       string
)
var tokenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new token (--admin for full access, --ephemeral, --ttl <duration>)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if ephemeralFlag && ttlFlag != "" {
			return fmt.Errorf("--ephemeral and --ttl are mutually exclusive")
		}
		if nameFlag == "" {
			return fmt.Errorf("--name is required")
		}

		scanner := bufio.NewScanner(os.Stdin)

		fmt.Print("description: ")
		scanner.Scan()
		description := strings.TrimSpace(scanner.Text())
		if description == "" {
			return fmt.Errorf("description is required")
		}

		role := "access"
		if adminFlag {
			role = "admin"
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
			Name:        nameFlag,
			Description: description,
			Role:        role,
			ExpiresAt:   expiresAt,
		}

		if role == "access" {
			fmt.Print("CIDRs (comma-separated, e.g. 10.0.0.1/32): ")
			scanner.Scan()
			cidrRaw := strings.TrimSpace(scanner.Text())
			if cidrRaw == "" {
				return fmt.Errorf("at least one CIDR is required for access tokens")
			}
			params.CIDRs = splitTrim(cidrRaw, ",")

			fmt.Print("namespaces (comma-separated, or blank): ")
			scanner.Scan()
			if ns := strings.TrimSpace(scanner.Text()); ns != "" {
				params.Namespaces = splitTrim(ns, ",")
			}

			fmt.Print("explicit keys (comma-separated, or blank): ")
			scanner.Scan()
			if ks := strings.TrimSpace(scanner.Text()); ks != "" {
				params.Keys = splitTrim(ks, ",")
			}

			if len(params.Namespaces) == 0 && len(params.Keys) == 0 {
				return fmt.Errorf("access token must have at least one namespace or key")
			}

			fmt.Print("writable? [y/N]: ")
			scanner.Scan()
			params.Writable = strings.ToLower(strings.TrimSpace(scanner.Text())) == "y"
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

		fmt.Printf("name:       %s\n", d.Name)
		fmt.Printf("secret:     %s\n", d.Secret)
		fmt.Printf("role:       %s\n", d.Role)
		if d.ExpiresAt != "" {
			fmt.Printf("expires-at: %s\n", d.ExpiresAt)
		}
		fmt.Println("copy the secret now — it will not be shown again")
		return nil
	},
}

func init() {
	tokenCreateCmd.Flags().StringVar(&nameFlag, "name", "", "unique slug name for the token, e.g. ops-box (required)")
	tokenCreateCmd.Flags().BoolVar(&adminFlag, "admin", false, "create an admin-role token with full vault access")
	tokenCreateCmd.Flags().BoolVar(&ephemeralFlag, "ephemeral", false, "process-scoped token, never written to disk")
	tokenCreateCmd.Flags().StringVar(&ttlFlag, "ttl", "", "time-to-live for the token, e.g. 24h or 30m")
}

var tokenListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all tokens",
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
		fmt.Fprintln(w, "NAME\tROLE\tDESCRIPTION\tCREATED\tLAST USED")
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
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				t.Name, t.Role, t.Description, created, lastUsed)
		}
		w.Flush()
		return nil
	},
}

// tokenRevokeCmd removes a single token by its name.
var tokenRevokeCmd = &cobra.Command{
	Use:   "revoke <name>",
	Short: "Revoke a token by name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := Client.Send(ipc.CmdTokenRevoke, ipc.TokenRevokeParams{Name: args[0]})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Printf("revoked %s\n", args[0])
		return nil
	},
}

// tokenRevokeAllCmd removes every persistent token after typing YES to confirm.
var tokenRevokeAllCmd = &cobra.Command{
	Use:   "revoke-all",
	Short: "Revoke all tokens (type YES to confirm)",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Print("type YES to revoke all tokens: ")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		if strings.TrimSpace(scanner.Text()) != "YES" {
			fmt.Println("aborted")
			return nil
		}
		resp, err := Client.Send(ipc.CmdTokenRevokeAll, nil)
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Println("all tokens revoked")
		return nil
	},
}

// splitTrim splits s on sep, trims whitespace from each part, and drops
// empty entries. Used to parse comma-separated CLI inputs like CIDR lists.
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
