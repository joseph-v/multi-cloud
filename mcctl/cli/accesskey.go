// Copyright 2019 The OpenSDS Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cli

import (
	"os"
	"github.com/spf13/cobra"
)

var accesskeyCommand = &cobra.Command{
	Use:   "ak",
	Short: "manage access keys",
	Run:   akAction,
}

var accesskeyCreateCommand = &cobra.Command{
	Use:   "create <accesskey> <secret key>",
	Short: "create an accesskey/secretkey pair (AK/SK)",
	Run:   accesskeyCreateAction,
}

// var accesskeyDeleteCommand = &cobra.Command{
// 	Use:   "delete <accesskey>",
// 	Short: "delete an accesskey (AK/SK)",
// 	Run:   accesskeyDeleteAction,
// }

// var accesskeyShowCommand = &cobra.Command{
// 	Use:   "show <id>",
// 	Short: "show an accesskey (AK/SK)",
// 	Run:   accesskeyShowAction,
// }

var accesskeyListCommand = &cobra.Command{
	Use:   "list",
	Short: "list all accesskeys (AK/SK)",
	Run:   accesskeyListAction,
}

// var accesskeyUpdateCommand = &cobra.Command{
// 	Use:   "update <access key> <secret key>",
// 	Short: "update an accesskey (AK/SK)",
// 	Run:   accesskeyUpdateAction,
// }

func init() {
	accesskeyCommand.AddCommand(accesskeyCreateCommand)
	// accesskeyCommand.AddCommand(accesskeyDeleteCommand)
	// accesskeyCommand.AddCommand(accesskeyShowCommand)
	accesskeyCommand.AddCommand(accesskeyListCommand)

	// accesskeyCommand.AddCommand(accesskeyUpdateCommand)
	// accesskeyUpdateCommand.Flags().StringVarP(&access, "access", "a", "", "the access of updated accesskey")
	// accesskeyUpdateCommand.Flags().StringVarP(&security, "security", "s", "", "the security of updated accesskey")

	// typeCommand.AddCommand(typeListCommand)
}

func akAction(cmd *cobra.Command, args []string) {
	cmd.Usage()
	os.Exit(1)
}

func accesskeyCreateAction(cmd *cobra.Command, args []string) {
	ArgsNumCheck(cmd, args, 2)
	resp, err := client.CreateAccessKey(args)
	if err != nil {

		Fatalln(HTTPErrStrip(err))
	}
	keys := KeyList{"Id", "TenantId", "UserId", "Name", "Type", "Region",
		"Endpoint", "BucketName", "Access", "Security"}
	PrintDict(resp, keys, FormatterList{})
}

// func accesskeyDeleteAction(cmd *cobra.Command, args []string) {
// 	// ArgsNumCheck(cmd, args, 1)
// 	// err := client.DeleteBackend(args[0])
// 	// if err != nil {
// 	// 	Fatalln(HTTPErrStrip(err))
// 	// }
// }

// func accesskeyShowAction(cmd *cobra.Command, args []string) {
// 	ArgsNumCheck(cmd, args, 1)
// 	// resp, err := client.GetBackend(args[0])
// 	// if err != nil {
// 	// 	Fatalln(HTTPErrStrip(err))
// 	// }
// 	// keys := KeyList{"Id", "TenantId", "UserId", "Name", "Type", "Region",
// 	// 	"Endpoint", "BucketName", "Access", "Security"}

// 	// PrintDict(resp, keys, FormatterList{})
// }

func accesskeyListAction(cmd *cobra.Command, args []string) {
	ArgsNumCheck(cmd, args, 0)
	resp, err := client.ListAccessKeys()
	if err != nil {
		Fatalln(HTTPErrStrip(err))
	}
	keys := KeyList{"Id", "Blob", "UserId", "Name", "Type"}
	PrintList(resp.Credential, keys, FormatterList{})
}

// func accesskeyUpdateAction(cmd *cobra.Command, args []string) {
// 	ArgsNumCheck(cmd, args, 1)
// 	// accesskey := &accesskey.UpdateBackendRequest{
// 	// 	Id:       args[0],
// 	// 	Access:   access,
// 	// 	Security: security,
// 	// }

// 	// resp, err := client.UpdateBackend(accesskey)
// 	// if err != nil {

// 	// 	Fatalln(HTTPErrStrip(err))
// 	// }
// 	// keys := KeyList{"Id", "TenantId", "UserId", "Name", "Type", "Region",
// 	// 	"Endpoint", "BucketName", "Access", "Security"}
// 	// PrintDict(resp, keys, FormatterList{})
// }
