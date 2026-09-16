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

// Package report exports the certificate inventory stored in SQLite to an
// XLSX spreadsheet suitable for review and sharing.
//
// Rows are ordered by urgency: expired first, then certificates in alert,
// then the healthy ones, and finally hosts without a parsed certificate
// (those carry only an error message).
package report

import (
	"certfinder/internal/storage"
	"database/sql"
	"fmt"

	"github.com/xuri/excelize/v2"
)

// ExportXLSX writes every certificate in the database to an XLSX file at
// path. If path is empty, the file is written to "certificates.xlsx" in the
// current directory.
func ExportXLSX(path string) error {
	if path == "" {
		path = defaultPath
	}

	rows, err := storage.QueryCertificates()
	if err != nil {
		return err
	}
	defer rows.Close()

	f, err := newWorkbook()
	if err != nil {
		return err
	}
	defer f.Close()

	written, err := fillSheet(f, rows)
	if err != nil {
		return err
	}

	if err := f.SaveAs(path); err != nil {
		return fmt.Errorf("saving %s: %w", path, err)
	}

	fmt.Printf("[+] Report saved: %s  (%d rows)\n", path, written)
	return nil
}



// newWorkbook creates a fresh XLSX file with a single sheet named
// "Certificates", the default sheet removed, and the header row already
// styled and pinned.
func newWorkbook() (*excelize.File, error) {
	f := excelize.NewFile()

	idx, err := f.NewSheet(sheetName)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("creating sheet: %w", err)
	}

	f.SetActiveSheet(idx)
	_ = f.DeleteSheet("Sheet1")

	if err := writeHeader(f); err != nil {
		f.Close()
		return nil, err
	}

	applyLayout(f)

	return f, nil
}



// writeHeader writes the column titles into row 1 and applies the shared
// header style (bold white on dark blue, centered).
func writeHeader(f *excelize.File) error {
	style, err := headerStyle(f)
	if err != nil {
		return fmt.Errorf("creating header style: %w", err)
	}

	for i, title := range headers {
		cell, err := excelize.CoordinatesToCellName(i+1, 1)
		
		if err != nil {
			return fmt.Errorf("computing header cell %d: %w", i+1, err)
		}
		_ = f.SetCellValue(sheetName, cell, title)
		_ = f.SetCellStyle(sheetName, cell, cell, style)
	}

	return nil
}



// headerStyle registers and returns a style index for the header row.
// Excelize styles are referenced by integer ID, so we create one per file
// and reuse it across every header cell.
func headerStyle(f *excelize.File) (int, error) {
	return f.NewStyle(&excelize.Style{
		Font: &excelize.Font{
			Bold: true, Color: "FFFFFF",
		},

		Fill: excelize.Fill{
			Type    : "pattern",
			Pattern : 1,
			Color   : []string{"305496"},
		},

		Alignment: &excelize.Alignment{
			Horizontal : "center",
			Vertical   : "center",
		},
	})
}



// applyLayout freezes the header row so it stays visible while scrolling,
// and sets the column widths declared in columnWidths.
//
// Errors from SetPanes/SetColWidth only occur on invalid coordinates, which
// cannot happen with the constants defined in this file, so they are safe
// to ignore.
func applyLayout(f *excelize.File) {
	_ = f.SetPanes(sheetName, &excelize.Panes{
		Freeze      : true,
		YSplit      : 1,
		TopLeftCell : "A2",
		ActivePane  : "bottomLeft",
	})

	for i, width := range columnWidths {
		col, err := excelize.ColumnNumberToName(i + 1)
		
		if err != nil {
			continue
		}
		_ = f.SetColWidth(sheetName, col, col, width)
	}
}



// fillSheet consumes every row from the query result and writes it to the
// sheet, starting at row 2. Returns the number of data rows written.
func fillSheet(f *excelize.File, rows *sql.Rows) (int, error) {
	written := 0

	for rows.Next() {
		row, err := scanRow(rows)
		if err != nil {
			return written, err
		}

		if err := writeRow(f, firstDataRow+written, row); err != nil {
			return written, err
		}
		
		written++
	}

	if err := rows.Err(); err != nil {
		return written, fmt.Errorf("reading rows: %w", err)
	}

	return written, nil
}



// scanRow scans the current cursor position into a slice of values ready to
// be handed to excelize. Cells that hold a NULL in the database become empty
// strings so the spreadsheet does not show "NULL" or "<nil>".
func scanRow(rows *sql.Rows) ([]interface{}, error) {
	var (
		name          sql.NullString
		commonName    sql.NullString
		notBefore     sql.NullString
		notAfter      sql.NullString
		remainingDays sql.NullInt64
		issuer        sql.NullString
		certType      sql.NullString
		expired       sql.NullInt64
		alert         sql.NullInt64
	)

	if err := rows.Scan(
		&name, &commonName, &notBefore, &notAfter,
		&remainingDays, &issuer, &certType,
		&expired, &alert,
	); err != nil {
		return nil, fmt.Errorf("scanning row: %w", err)
	}

	// Days only makes sense when a certificate was actually parsed.
	// Hosts that failed TLS have no not_after, so we blank the cell.
	days := any("")
	if notAfter.Valid {
		days = remainingDays.Int64
	}

	return []any{
		name.String,
		commonName.String,
		truncDate(notBefore.String),
		truncDate(notAfter.String),
		days,
		issuer.String,
		certType.String,
	}, nil
}



// writeRow places the given values into rowIdx, one value per column.
//
// Errors from SetCellValue only occur on invalid column indexes, which are
// bounded by the length of the value slice, so they are ignored.
func writeRow(f *excelize.File, rowIdx int, values []any) error {
	for i, v := range values {
		cell, err := excelize.CoordinatesToCellName(i+1, rowIdx)
		
		if err != nil {
			return fmt.Errorf("computing cell (%d, %d): %w", i+1, rowIdx, err)
		}
		_ = f.SetCellValue(sheetName, cell, v)
	}
	return nil
}



// truncDate keeps only the YYYY-MM-DD portion of an ISO 8601 timestamp.
// Values shorter than 10 bytes (including the empty string) are returned
// unchanged.
func truncDate(s string) string {
	if len(s) >= 10 {
		return s[:10]
	}

	return s
}