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


func initDB() (*sql.DB, error) {
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
	db, err := initDB()
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
	db, err := initDB()
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