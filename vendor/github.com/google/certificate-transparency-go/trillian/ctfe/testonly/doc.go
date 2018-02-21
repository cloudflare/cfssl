// Copyright 2016 Google Inc. All Rights Reserved.
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

/*
Package testonly contains code and data that should only be used by tests.
Production code MUST NOT depend on anything in this package. This will be enforced
by tools where possible.

As an example PEM encoded test certificates and helper functions to decode them are
suitable candidates for being placed in testonly.

This package should only contain CT specific code and certificate data.
*/
package testonly
