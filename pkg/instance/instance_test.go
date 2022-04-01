package instance

import (
	"net/http"
	"testing"
)

func CheckHTTPMethod(t *testing.T) {
	var instance Instance
	for _, table := range []struct {
		method string
		wantOK bool
	}{
		{wantOK: false, method: http.MethodHead},
		{wantOK: true, method: http.MethodPost},
		{wantOK: true, method: http.MethodGet},
	} {
		ok := instance.checkHTTPMethod(table.method)
		if got, want := ok, table.wantOK; got != want {
			t.Errorf("%s: got %v but wanted %v", table.method, got, want)
		}
	}
}
