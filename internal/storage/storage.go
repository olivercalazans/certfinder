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
	"time"

	"certfinder/internal/models"

	_ "modernc.org/sqlite"
)

const DBPath = "certificates.db"

const schema = `
CREATE TABLE IF NOT EXISTS certificates (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    error           TEXT    NOT NULL DEFAULT '',
    issuer          TEXT    NOT NULL DEFAULT '',
    cert_type       TEXT    NOT NULL DEFAULT '',
    common_name     TEXT    NOT NULL DEFAULT '',
    not_before      TEXT,
    not_after       TEXT,
    remaining_days  INTEGER NOT NULL DEFAULT 0,
    expired         INTEGER NOT NULL DEFAULT 0,
    alert           INTEGER NOT NULL DEFAULT 0,
    first_seen      TEXT    NOT NULL,
    last_seen       TEXT    NOT NULL,
    last_checked    TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remaining ON certificates(remaining_days);
CREATE INDEX IF NOT EXISTS idx_alert     ON certificates(alert);
CREATE INDEX IF NOT EXISTS idx_expired   ON certificates(expired);
CREATE INDEX IF NOT EXISTS idx_last_seen ON certificates(last_seen);
`

func InitDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", DBPath)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func dtToStr(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func UpsertDomains(domains []models.Domain) error {
	db, err := InitDB()
	if err != nil {
		return err
	}
	defer db.Close()

	now := time.Now().UTC().Format(time.RFC3339)

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO certificates (
			name, error, issuer, cert_type, common_name,
			not_before, not_after, remaining_days,
			expired, alert,
			first_seen, last_seen, last_checked
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			error          = excluded.error,
			issuer         = excluded.issuer,
			cert_type      = excluded.cert_type,
			common_name    = excluded.common_name,
			not_before     = excluded.not_before,
			not_after      = excluded.not_after,
			remaining_days = excluded.remaining_days,
			expired        = excluded.expired,
			alert          = excluded.alert,
			last_seen      = excluded.last_seen,
			last_checked   = excluded.last_checked
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, d := range domains {
		_, err := stmt.Exec(
			d.Name, d.Error, d.Issuer, d.CertType, d.CommonName,
			dtToStr(d.NotBefore), dtToStr(d.NotAfter), d.RemainingDays,
			boolToInt(d.Expired), boolToInt(d.Alert),
			now, now, now,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func fetchRows(query string, args ...interface{}) ([]map[string]interface{}, error) {
	db, err := InitDB()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	var out []map[string]interface{}
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]interface{}, len(cols))
		for i, c := range cols {
			row[c] = vals[i]
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

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

