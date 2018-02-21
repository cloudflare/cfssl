// Copyright 2017 Google Inc. All Rights Reserved.
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

package util

import (
	"errors"
	"fmt"
	"strings"

	"google.golang.org/grpc/naming"
)

// fixedBackends implements the naming.Watcher interface by returning
// a fixed set of servers.
type fixedBackends struct {
	pendingServers []string
	done           chan struct{}
}

func newFixedBackends(servers []string) *fixedBackends {
	return &fixedBackends{
		pendingServers: servers,
		done:           make(chan struct{}),
	}
}

// Next returns a set of updates describing changes to available servers;
// it will return the original set on first invocation, and block forever
// thereafter.
func (fb *fixedBackends) Next() ([]*naming.Update, error) {
	if len(fb.pendingServers) == 0 {
		// Block until there is an update.  There will never be an update, so
		// this blocks until Close() closes the channel.
		<-fb.done
		return nil, errors.New("watcher closed")
	}
	updates := make([]*naming.Update, len(fb.pendingServers))
	for i, server := range fb.pendingServers {
		updates[i] = &naming.Update{Op: naming.Add, Addr: server}
	}
	fb.pendingServers = nil
	return updates, nil
}

// Close terminates the Watcher.
func (fb *fixedBackends) Close() {
	close(fb.done)
}

// FixedBackendResolver implements the naming.Resolver interface by
// just returning a fixedBackends object for the comma-separated names
// in the target.
type FixedBackendResolver struct{}

// Resolve returns a fixedBackends object for the given target.
func (f FixedBackendResolver) Resolve(target string) (naming.Watcher, error) {
	backends := strings.Split(target, ",")
	if len(backends) == 0 || (len(backends) == 1 && backends[0] == "") {
		return nil, fmt.Errorf("no backends found in %v", target)
	}
	return newFixedBackends(backends), nil
}
