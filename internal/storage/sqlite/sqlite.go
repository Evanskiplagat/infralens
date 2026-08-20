// Package sqlite implements storage.Store on top of a local SQLite
// database file, InfraLens's default persistence for scan history.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver: no cgo toolchain required

	"infralens/internal/findings"
	"infralens/internal/resource"
)

//go:embed schema.sql
var schema string

// Store is a storage.Store backed by a SQLite database file.
type Store struct {
	db *sql.DB
}

// Open creates (if needed) and migrates the database at path.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1) // avoid SQLITE_BUSY from concurrent writers within one process

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CreateScan(ctx context.Context, scan resource.Scan) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scans (id, account_id, profile, regions, started_at, status) VALUES (?, ?, ?, ?, ?, ?)`,
		scan.ID, scan.AccountID, scan.Profile, strings.Join(scan.Regions, ","), scan.StartedAt, string(scan.Status),
	)
	return err
}

func (s *Store) FinishScan(ctx context.Context, scanID string, status resource.ScanStatus, scanErr string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE scans SET status = ?, finished_at = ?, error = ? WHERE id = ?`,
		string(status), time.Now().UTC(), scanErr, scanID,
	)
	return err
}

func (s *Store) SaveResources(ctx context.Context, scanID string, resources []resource.Resource) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO resources (id, scan_id, provider_id, kind, name, region, account_id, tags, attributes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, r := range resources {
		tags, err := json.Marshal(r.Tags)
		if err != nil {
			return err
		}
		attrs, err := json.Marshal(r.Attributes)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, r.ID, scanID, r.ProviderID, string(r.Kind), r.Name, r.Region, r.AccountID, tags, attrs); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SaveEdges(ctx context.Context, scanID string, edges []resource.Edge) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO edges (id, scan_id, from_id, to_id, type) VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range edges {
		if _, err := stmt.ExecContext(ctx, e.ID, scanID, e.From, e.To, string(e.Type)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SaveFindings(ctx context.Context, scanID string, fs []findings.Finding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO findings (scan_id, rule_id, resource_id, severity, title, description) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range fs {
		if _, err := stmt.ExecContext(ctx, scanID, f.RuleID, f.ResourceID, string(f.Severity), f.Title, f.Description); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type scanRow struct {
	ID         string
	AccountID  string
	Profile    string
	Regions    string
	StartedAt  time.Time
	FinishedAt sql.NullTime
	Status     string
	Error      sql.NullString
}

func scanFromRow(r scanRow) resource.Scan {
	sc := resource.Scan{
		ID:        r.ID,
		AccountID: r.AccountID,
		Profile:   r.Profile,
		StartedAt: r.StartedAt,
		Status:    resource.ScanStatus(r.Status),
		Error:     r.Error.String,
	}
	if r.Regions != "" {
		sc.Regions = strings.Split(r.Regions, ",")
	}
	if r.FinishedAt.Valid {
		sc.FinishedAt = r.FinishedAt.Time
	}
	return sc
}

const scanColumns = `id, account_id, profile, regions, started_at, finished_at, status, error`

func (s *Store) GetScan(ctx context.Context, scanID string) (resource.Scan, error) {
	var r scanRow
	err := s.db.QueryRowContext(ctx, `SELECT `+scanColumns+` FROM scans WHERE id = ?`, scanID).
		Scan(&r.ID, &r.AccountID, &r.Profile, &r.Regions, &r.StartedAt, &r.FinishedAt, &r.Status, &r.Error)
	if err != nil {
		return resource.Scan{}, err
	}
	return scanFromRow(r), nil
}

func (s *Store) LatestScan(ctx context.Context) (resource.Scan, error) {
	var r scanRow
	err := s.db.QueryRowContext(ctx, `SELECT `+scanColumns+` FROM scans ORDER BY started_at DESC LIMIT 1`).
		Scan(&r.ID, &r.AccountID, &r.Profile, &r.Regions, &r.StartedAt, &r.FinishedAt, &r.Status, &r.Error)
	if err != nil {
		return resource.Scan{}, err
	}
	return scanFromRow(r), nil
}

func (s *Store) ListScans(ctx context.Context) ([]resource.Scan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+scanColumns+` FROM scans ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []resource.Scan
	for rows.Next() {
		var r scanRow
		if err := rows.Scan(&r.ID, &r.AccountID, &r.Profile, &r.Regions, &r.StartedAt, &r.FinishedAt, &r.Status, &r.Error); err != nil {
			return nil, err
		}
		out = append(out, scanFromRow(r))
	}
	return out, rows.Err()
}

func (s *Store) LoadResources(ctx context.Context, scanID string) ([]resource.Resource, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, provider_id, kind, name, region, account_id, tags, attributes FROM resources WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []resource.Resource
	for rows.Next() {
		var (
			r         resource.Resource
			kind      string
			tagsJSON  string
			attrsJSON string
		)
		if err := rows.Scan(&r.ID, &r.ProviderID, &kind, &r.Name, &r.Region, &r.AccountID, &tagsJSON, &attrsJSON); err != nil {
			return nil, err
		}
		r.Kind = resource.Kind(kind)
		if err := json.Unmarshal([]byte(tagsJSON), &r.Tags); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(attrsJSON), &r.Attributes); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) LoadEdges(ctx context.Context, scanID string) ([]resource.Edge, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, from_id, to_id, type FROM edges WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []resource.Edge
	for rows.Next() {
		var e resource.Edge
		var t string
		if err := rows.Scan(&e.ID, &e.From, &e.To, &t); err != nil {
			return nil, err
		}
		e.Type = resource.RelationType(t)
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) LoadFindings(ctx context.Context, scanID string) ([]findings.Finding, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT rule_id, resource_id, severity, title, description FROM findings WHERE scan_id = ?`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []findings.Finding
	for rows.Next() {
		var f findings.Finding
		var severity string
		if err := rows.Scan(&f.RuleID, &f.ResourceID, &severity, &f.Title, &f.Description); err != nil {
			return nil, err
		}
		f.Severity = findings.Severity(severity)
		out = append(out, f)
	}
	return out, rows.Err()
}
