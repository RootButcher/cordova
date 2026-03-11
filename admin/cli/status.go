// cordova/admin/cli/status.go

package cli

import (
	"encoding/json"
	"fmt"

	"cordova/core/ipc"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show vault status and daemon version",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := Client.Send(ipc.CmdStatus, nil)
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		var d ipc.StatusData
		if err := json.Unmarshal(resp.Data, &d); err != nil {
			return err
		}
		state := "unsealed"
		if d.Sealed {
			state = "sealed"
		}
		fmt.Printf("status:  %s\nversion: %s\n", state, d.Version)
		return nil
	},
}
var sealCmd = &cobra.Command{
	Use:   "seal",
	Short: "Seal the vault and stop the daemon",
	RunE: func(cmd *cobra.Command, args []string) error {
		resp, err := Client.Send(ipc.CmdSeal, nil)
		if err != nil {
			return err
		}
		if !resp.OK {
			return fmt.Errorf("%s", resp.Error)
		}
		fmt.Println("sealing")
		return nil
	},
}
