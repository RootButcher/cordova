// cordova/admin/cli/user.go

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"cordova/core/ipc"
)

var userCmd = &cobra.Command{
	Use:   "user",
	Short: "User tree management",
}

func init() {
	userCmd.AddCommand(userCreateCmd)
	userCmd.AddCommand(userListCmd)
	userCmd.AddCommand(userDeleteCmd)
}

var userCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new user as a child of an existing user",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		parent, _ := cmd.Flags().GetString("parent")
		admin, _ := cmd.Flags().GetBool("admin")
		writable, _ := cmd.Flags().GetBool("writable")
		nsRaw, _ := cmd.Flags().GetString("namespaces")
		keysRaw, _ := cmd.Flags().GetString("keys")
		socketsRaw, _ := cmd.Flags().GetString("sockets")

		if name == "" {
			return fmt.Errorf("--name is required")
		}
		if parent == "" {
			return fmt.Errorf("--parent is required")
		}

		var namespaces, keys, sockets []string
		if nsRaw != "" {
			namespaces = splitTrim(nsRaw, ",")
		}
		if keysRaw != "" {
			keys = splitTrim(keysRaw, ",")
		}
		if socketsRaw != "" {
			sockets = splitTrim(socketsRaw, ",")
		}

		resp, err := Client.Send(ipc.CmdUserAdd, ipc.UserAddParams{
			Name:       name,
			Parent:     parent,
			Admin:      admin,
			Namespaces: namespaces,
			Keys:       keys,
			Sockets:    sockets,
			Writable:   writable,
		})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		var d ipc.AckData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return err
		}
		fmt.Println(d.Message)
		return nil
	},
}

func init() {
	userCreateCmd.Flags().String("name", "", "unique user slug (required)")
	userCreateCmd.Flags().String("parent", "", "parent user name (required)")
	userCreateCmd.Flags().Bool("admin", false, "grant admin privileges")
	userCreateCmd.Flags().Bool("writable", false, "allow write access to keys")
	userCreateCmd.Flags().String("namespaces", "", "comma-separated allowed namespaces")
	userCreateCmd.Flags().String("keys", "", "comma-separated allowed key names")
	userCreateCmd.Flags().String("sockets", "", "comma-separated allowed socket names")
}

var userListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all users in the tree",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := Client.Send(ipc.CmdUserList, nil)
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		var d ipc.UserListData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return err
		}
		if len(d.Users) == 0 {
			fmt.Println("no users")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "NAME\tPARENT\tADMIN\tWRITABLE\tTOKENS\tCREATED")
		for _, u := range d.Users {
			created := ""
			if ts, err := time.Parse(time.RFC3339, u.CreatedAt); err == nil {
				created = ts.Format("2006-01-02")
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%v\t%v\t%d\t%s\n",
				u.Name, u.Parent, u.Admin, u.Writable, u.TokenCount, created)
		}
		_ = w.Flush()
		return nil
	},
}

var userDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a user (blocked if the user has children)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := Client.Send(ipc.CmdUserDelete, ipc.UserDeleteParams{Name: args[0]})
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		var d ipc.AckData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return err
		}
		fmt.Println(d.Message)
		return nil
	},
}
