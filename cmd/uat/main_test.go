/* UAT 网络边界测试：私网 Edge 验收必须使用精确 RFC1918 地址和 HTTPS，不能扩大到公共或通配监听。 */
package main

import "testing"

func TestValidateUATNetworkBoundary(t *testing.T) {
	accepted := []struct {
		address string
		origin  string
	}{
		{address: "127.0.0.1:9692", origin: "http://localhost:9692"},
		{address: "192.168.244.128:9692", origin: "https://192.168.244.128:9692"},
		{address: "10.20.30.40:9692", origin: "https://10.20.30.40:9692"},
		{address: "172.20.1.4:9692", origin: "https://172.20.1.4:9692"},
	}
	for _, candidate := range accepted {
		if validationError := validateUATNetworkBoundary(candidate.address, candidate.origin); validationError != nil {
			t.Fatalf("expected approved UAT boundary to pass: %v", validationError)
		}
	}

	rejected := []struct {
		address string
		origin  string
	}{
		{address: "0.0.0.0:9692", origin: "https://192.168.244.128:9692"},
		{address: "8.8.8.8:9692", origin: "https://8.8.8.8:9692"},
		{address: "192.168.244.128:9692", origin: "http://192.168.244.128:9692"},
		{address: "192.168.244.128:9692", origin: "https://192.168.244.129:9692"},
		{address: "192.168.244.128:8081", origin: "https://192.168.244.128:8081"},
	}
	for _, candidate := range rejected {
		if validationError := validateUATNetworkBoundary(candidate.address, candidate.origin); validationError == nil {
			t.Fatal("expected unsafe UAT boundary to be rejected")
		}
	}
}
