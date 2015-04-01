package signer

import (
	"testing"
)

func TestSplitHosts(t *testing.T) {
	list := SplitHosts("")
	if list != nil {
		t.Fatal("SplitHost should return nil with empty input")
	}

	list = SplitHosts("single.domain")
	if len(list) != 1 {
		t.Fatal("SplitHost fails to split single domain")
	}

	list = SplitHosts("comma,separated,values")
	if len(list) != 3 {
		t.Fatal("SplitHost fails to split multiple domains")
	}
	if list[0] != "comma" || list[1] != "separated" || list[2] != "values" {
		t.Fatal("SplitHost fails to split multiple domains")
	}
}
