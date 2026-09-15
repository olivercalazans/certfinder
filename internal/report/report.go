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

package report

import (
	"database/sql"
	"fmt"

	"certfinder/internal/storage"

	"github.com/xuri/excelize/v2"
)

var headers = []string{
	"Domain",
	"Common Name",
	"Not Before",
	"Not After",
	"Days Remaining",
	"Issuer",
	"Cert Type",
}

var columnWidths = []float64{45, 30, 14, 14, 16, 35, 16}

func ExportXLSX(path string) error {
	if path == "" {
		path = "certificates.xlsx"
	}

	db, err := storage.InitDB()
	if err != nil {
		return err
	}
	defer db.Close()

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
		return err
	}
	defer rows.Close()

	f := excelize.NewFile()
	defer f.Close()

	const sheet = "Certificates"
	idx, err := f.NewSheet(sheet)
	if err != nil {
		return err
	}
	f.SetActiveSheet(idx)
	_ = f.DeleteSheet("Sheet1")

	headerStyle, err := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill: excelize.Fill{
			Type:    "pattern",
			Pattern: 1,
			Color:   []string{"305496"},
		},
		Alignment: &excelize.Alignment{
			Horizontal: "center",
			Vertical:   "center",
		},
	})
	if err != nil {
		return err
	}

	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		_ = f.SetCellValue(sheet, cell, h)
		_ = f.SetCellStyle(sheet, cell, cell, headerStyle)
	}

	_ = f.SetPanes(sheet, &excelize.Panes{
		Freeze:      true,
		YSplit:      1,
		TopLeftCell: "A2",
		ActivePane:  "bottomLeft",
	})

	for i, w := range columnWidths {
		col, _ := excelize.ColumnNumberToName(i + 1)
		_ = f.SetColWidth(sheet, col, col, w)
	}

	rowIdx := 2
	for rows.Next() {
		var (
			name, commonName, notBefore, notAfter sql.NullString
			issuer, certType                      sql.NullString
			remainingDays                         sql.NullInt64
			expired, alert                        sql.NullInt64
		)

		err := rows.Scan(
			&name, &commonName, &notBefore, &notAfter,
			&remainingDays, &issuer, &certType,
			&expired, &alert,
		)
		if err != nil {
			return err
		}

		var days interface{}
		if notAfter.Valid {
			days = remainingDays.Int64
		} else {
			days = ""
		}

		values := []interface{}{
			name.String,
			commonName.String,
			truncDate(notBefore.String),
			truncDate(notAfter.String),
			days,
			issuer.String,
			certType.String,
		}

		for i, v := range values {
			cell, _ := excelize.CoordinatesToCellName(i+1, rowIdx)
			_ = f.SetCellValue(sheet, cell, v)
		}
		rowIdx++
	}

	if err := rows.Err(); err != nil {
		return err
	}

	if err := f.SaveAs(path); err != nil {
		return err
	}

	fmt.Printf("[+] Report saved: %s  (%d rows)\n", path, rowIdx-2)
	return nil
}

func truncDate(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}
	return s
}
