## fgt
fgt runs any command for you and exits with exitcode 1 when the child process sent anythingto stdout or stderr

### Installation
`go get github.com/GeertJohan/fgt`


### Usage
Some examples:

`fgt true` will return successfully

`fgt false` will return with exitcode 1

`fgt echo hi` will return with exitcode 1 (even though echo returned with exitcode 0)

`fgt gofmt -l <yourpackage>` will return with exitcode 1 when gofmt indicates something must be formatted diferently

### History
This command was created to make sure jenkins will complain when gofmt needs something formatted.
