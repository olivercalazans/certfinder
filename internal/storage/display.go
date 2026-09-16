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

package storage

import "fmt"



func intOrZero(v interface{}) int64 {
	if v == nil {
		return 0
	}
	if n, ok := v.(int64); ok {
		return n
	}
	return 0
}



// DisplayStats prints a one-line summary of the database: total hosts,
// certificates in OK state, in alert (expiring within 30 days), already
// expired, and entries with a non-empty error field.
func DisplayStats() {
	s, err := getStats()

	if err != nil {
		fmt.Printf("[ err ] stats: %v\n", err)
		return
	}

	total   := intOrZero(s["total"])
	expired := intOrZero(s["expirados"])
	alert   := intOrZero(s["alerta"])
	errors  := intOrZero(s["erros"])
	
	ok := total - expired - alert - errors

	fmt.Printf(
		"\nTOTAL: %d  |  OK: %d  |  Alert: %d  |  Expired: %d  |  Error: %d\n",
		total, ok, alert, expired, errors,
	)
}



// DisplayAlerts prints every host whose certificate is expired, in alert,
// or that currently holds an error, ordered by urgency (expired first, then
// by remaining days). One line per host.
func DisplayAlerts() {
	alerts, err := getAlerts()
	if err != nil {
		fmt.Printf("[ err ] alerts: %v\n", err)
		return
	}
	if len(alerts) == 0 {
		return
	}

	fmt.Printf("\nWARNING (%d):\n\n", len(alerts))

	for _, a := range alerts {
		name := fmt.Sprint(a["name"])
		errMsg := fmt.Sprint(a["error"])

		if errMsg != "" {
			msg := errMsg
			if len(msg) > 60 {
				msg = msg[:60]
			}
			fmt.Printf("  %-45s %s\n", name, msg)
			continue
		}

		days := intOrZero(a["remaining_days"])
		expired := intOrZero(a["expired"]) == 1

		if expired {
			fmt.Printf("  %-45s expired %d days ago\n", name, -days)
		} else {
			fmt.Printf("  %-45s will expire in %d days\n", name, days)
		}
	}
}



// DisplayStale prints hosts whose last_seen is older than the given number
// of days — typically indicating subdomains that the enumeration step stopped
// returning. Output is capped at limit rows; the remainder is summarized
// with a trailing count.
func DisplayStale(days int, limit int) {
	stale, err := getStale(days)
	if err != nil {
		fmt.Printf("[ err ] stale: %v\n", err)
		return
	}
	if len(stale) == 0 {
		return
	}

	fmt.Printf("\nNot seen in %d+ days (%d):\n\n", days, len(stale))

	for i, d := range stale {
		if i >= limit {
			break
		}
		name := fmt.Sprint(d["name"])
		last := fmt.Sprint(d["last_seen"])
		if len(last) >= 10 {
			last = last[:10]
		}
		fmt.Printf("  %-50s last seen: %s\n", name, last)
	}

	if len(stale) > limit {
		fmt.Printf("  ... and %d more\n", len(stale)-limit)
	}
}
