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

import (
	"database/sql"
	"fmt"
)


func getStats() (map[string]interface{}, error) {
	rows, err := fetchRows(`
		SELECT
			COUNT(*)                   AS total,
			SUM(expired)               AS expirados,
			SUM(alert AND NOT expired) AS alerta,
			SUM(error != '')           AS erros,
			AVG(remaining_days)        AS media_dias,
			MIN(last_seen)             AS visto_mais_antigo
		FROM certificates
	`)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return map[string]interface{}{}, nil
	}
	return rows[0], nil
}



func getAlerts() ([]map[string]interface{}, error) {
	return fetchRows(`
		SELECT name, issuer, cert_type, not_after, remaining_days,
		       expired, alert, error, last_seen
		FROM certificates
		WHERE expired = 1 OR alert = 1 OR error != ''
		ORDER BY expired DESC, remaining_days ASC
	`)
}



func getStale(days int) ([]map[string]interface{}, error) {
	return fetchRows(`
		SELECT name, issuer, not_after, remaining_days, last_seen
		FROM certificates
		WHERE julianday('now') - julianday(last_seen) >= ?
		ORDER BY last_seen ASC
	`, days)
}



// QueryCertificates returns all rows from the certificates table, already
// ordered by urgency (expired, alert, healthy, then failures by name).
//
// The caller is responsible for closing the returned *sql.Rows.
func QueryCertificates() (*sql.Rows, error) {
	db, err := initDB()
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	rows, err := db.Query(`
		SELECT name, common_name, not_before, not_after,
		       remaining_days, issuer, cert_type,
		       expired, alert
		FROM certificates
		ORDER BY
			expired   DESC,
			alert     DESC,
			CASE WHEN not_after IS NULL THEN 1 ELSE 0 END,
			remaining_days ASC,
			name ASC
	`)

	if err != nil {
		db.Close()
		return nil, fmt.Errorf("querying certificates: %w", err)
	}

	return rows, nil
}