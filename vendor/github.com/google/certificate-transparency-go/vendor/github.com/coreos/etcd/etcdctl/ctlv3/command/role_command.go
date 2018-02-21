// Copyright 2016 The etcd Authors
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

package command

import (
	"fmt"

	"github.com/coreos/etcd/clientv3"
	"github.com/spf13/cobra"
	"golang.org/x/net/context"
)

var (
	grantPermissionPrefix bool
)

// NewRoleCommand returns the cobra command for "role".
func NewRoleCommand() *cobra.Command {
	ac := &cobra.Command{
		Use:   "role <subcommand>",
		Short: "Role related commands",
	}

	ac.AddCommand(newRoleAddCommand())
	ac.AddCommand(newRoleDeleteCommand())
	ac.AddCommand(newRoleGetCommand())
	ac.AddCommand(newRoleListCommand())
	ac.AddCommand(newRoleGrantPermissionCommand())
	ac.AddCommand(newRoleRevokePermissionCommand())

	return ac
}

func newRoleAddCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "add <role name>",
		Short: "Adds a new role",
		Run:   roleAddCommandFunc,
	}
}

func newRoleDeleteCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <role name>",
		Short: "Deletes a role",
		Run:   roleDeleteCommandFunc,
	}
}

func newRoleGetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "get <role name>",
		Short: "Gets detailed information of a role",
		Run:   roleGetCommandFunc,
	}
}

func newRoleListCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Lists all roles",
		Run:   roleListCommandFunc,
	}
}

func newRoleGrantPermissionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant-permission [options] <role name> <permission type> <key> [endkey]",
		Short: "Grants a key to a role",
		Run:   roleGrantPermissionCommandFunc,
	}

	cmd.Flags().BoolVar(&grantPermissionPrefix, "prefix", false, "grant a prefix permission")

	return cmd
}

func newRoleRevokePermissionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke-permission <role name> <key> [endkey]",
		Short: "Revokes a key from a role",
		Run:   roleRevokePermissionCommandFunc,
	}
}

// roleAddCommandFunc executes the "role add" command.
func roleAddCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		ExitWithError(ExitBadArgs, fmt.Errorf("role add command requires role name as its argument."))
	}

	resp, err := mustClientFromCmd(cmd).Auth.RoleAdd(context.TODO(), args[0])
	if err != nil {
		ExitWithError(ExitError, err)
	}

	display.RoleAdd(args[0], *resp)
}

// roleDeleteCommandFunc executes the "role delete" command.
func roleDeleteCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		ExitWithError(ExitBadArgs, fmt.Errorf("role delete command requires role name as its argument."))
	}

	resp, err := mustClientFromCmd(cmd).Auth.RoleDelete(context.TODO(), args[0])
	if err != nil {
		ExitWithError(ExitError, err)
	}

	display.RoleDelete(args[0], *resp)
}

// roleGetCommandFunc executes the "role get" command.
func roleGetCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) != 1 {
		ExitWithError(ExitBadArgs, fmt.Errorf("role get command requires role name as its argument."))
	}

	name := args[0]
	resp, err := mustClientFromCmd(cmd).Auth.RoleGet(context.TODO(), name)
	if err != nil {
		ExitWithError(ExitError, err)
	}

	display.RoleGet(name, *resp)
}

// roleListCommandFunc executes the "role list" command.
func roleListCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) != 0 {
		ExitWithError(ExitBadArgs, fmt.Errorf("role list command requires no arguments."))
	}

	resp, err := mustClientFromCmd(cmd).Auth.RoleList(context.TODO())
	if err != nil {
		ExitWithError(ExitError, err)
	}

	display.RoleList(*resp)
}

// roleGrantPermissionCommandFunc executes the "role grant-permission" command.
func roleGrantPermissionCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) < 3 {
		ExitWithError(ExitBadArgs, fmt.Errorf("role grant command requires role name, permission type, and key [endkey] as its argument."))
	}

	perm, err := clientv3.StrToPermissionType(args[1])
	if err != nil {
		ExitWithError(ExitBadArgs, err)
	}

	rangeEnd := ""
	if 4 <= len(args) {
		if grantPermissionPrefix {
			ExitWithError(ExitBadArgs, fmt.Errorf("don't pass both of --prefix option and range end to grant permission command"))
		}
		rangeEnd = args[3]
	} else if grantPermissionPrefix {
		rangeEnd = clientv3.GetPrefixRangeEnd(args[2])
	}

	resp, err := mustClientFromCmd(cmd).Auth.RoleGrantPermission(context.TODO(), args[0], args[2], rangeEnd, perm)
	if err != nil {
		ExitWithError(ExitError, err)
	}

	display.RoleGrantPermission(args[0], *resp)
}

// roleRevokePermissionCommandFunc executes the "role revoke-permission" command.
func roleRevokePermissionCommandFunc(cmd *cobra.Command, args []string) {
	if len(args) < 2 {
		ExitWithError(ExitBadArgs, fmt.Errorf("role revoke-permission command requires role name and key [endkey] as its argument."))
	}

	rangeEnd := ""
	if 3 <= len(args) {
		rangeEnd = args[2]
	}

	resp, err := mustClientFromCmd(cmd).Auth.RoleRevokePermission(context.TODO(), args[0], args[1], rangeEnd)
	if err != nil {
		ExitWithError(ExitError, err)
	}
	display.RoleRevokePermission(args[0], args[1], rangeEnd, *resp)
}
