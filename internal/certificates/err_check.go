// Copyright 2026 Oliver R. Calazans Jeronimo
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

package certificates

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
)



func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	return false
}



func isRefusedError(err error) bool {
	if opErr, ok := errors.AsType[*net.OpError](err); ok {
		return strings.Contains(strings.ToLower(opErr.Error()), "connection refused")
	}

	return false
}



func isCertVerifyError(err error) bool {
	if _, ok := errors.AsType[*tls.CertificateVerificationError](err); ok {
		return true
	}

	if _, ok := errors.AsType[*x509.UnknownAuthorityError](err); ok {
		return true
	}
	
	if _, ok := errors.AsType[x509.HostnameError](err); ok {
		return true
	}
	
	if _, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
		return true
	}
	
	return false
}