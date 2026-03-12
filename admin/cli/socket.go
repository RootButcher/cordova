// cordova/admin/cli/socket.go

package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"cordova/core/ipc"
)

var socketCmd = &cobra.Command{
	Use:   "socket",
	Short: "Socket management",
}

func init() {
	socketCmd.AddCommand(socketListCmd)
	socketCmd.AddCommand(socketAddCmd)
	socketCmd.AddCommand(socketDeleteCmd)
}

var socketListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all configured sockets",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := Client.Send(ipc.CmdSocketList, nil)
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		var d ipc.SocketListData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return err
		}
		if len(d.Sockets) == 0 {
			fmt.Println("no sockets configured")
			return nil
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "NAME\tPATH\tUNRESTRICTED\tWRITABLE\tLIVE")
		for _, s := range d.Sockets {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%v\t%v\t%v\n",
				s.Name, s.Path, s.Scope.Unrestricted, s.Scope.Writable, s.Live)
		}
		_ = w.Flush()
		return nil
	},
}

var socketAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add and start a new socket",
	RunE: func(cmd *cobra.Command, args []string) error {
		name, _ := cmd.Flags().GetString("name")
		path, _ := cmd.Flags().GetString("path")
		unrestricted, _ := cmd.Flags().GetBool("unrestricted")
		writable, _ := cmd.Flags().GetBool("writable")
		nsRaw, _ := cmd.Flags().GetString("namespaces")
		keysRaw, _ := cmd.Flags().GetString("keys")

		if name == "" {
			return fmt.Errorf("--name is required")
		}
		if path == "" {
			return fmt.Errorf("--path is required")
		}

		scope := ipc.SocketScope{
			Unrestricted: unrestricted,
			Writable:     writable,
		}
		if nsRaw != "" {
			scope.Namespaces = splitTrim(nsRaw, ",")
		}
		if keysRaw != "" {
			scope.Keys = splitTrim(keysRaw, ",")
		}

		resp, err := Client.Send(ipc.CmdSocketAdd, ipc.SocketAddParams{
			Name:  name,
			Path:  path,
			Scope: scope,
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
	socketAddCmd.Flags().String("name", "", "unique socket name slug (required)")
	socketAddCmd.Flags().String("path", "", "filesystem path for the socket file (required)")
	socketAddCmd.Flags().Bool("unrestricted", false, "allow all operations on this socket")
	socketAddCmd.Flags().Bool("writable", false, "allow write operations")
	socketAddCmd.Flags().String("namespaces", "", "comma-separated allowed namespaces")
	socketAddCmd.Flags().String("keys", "", "comma-separated allowed key names")
}

var socketDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Stop and remove a socket",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := Client.Send(ipc.CmdSocketDelete, ipc.SocketDeleteParams{Name: args[0]})
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
