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
Package ctfe contains a usage example by providing an implementation of an RFC6962 compatible CT
log server using a Trillian log server as backend storage via its GRPC API.

IMPORTANT: Only code rooted within this part of the tree should refer to the CT
Github repository. Other parts of the system must not assume that the data they're
processing is X.509 or CT related.

The CT repository can be found at: https://github.com/google/certificate-transparency
*/
package ctfe
