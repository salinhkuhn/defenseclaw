package audit

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Actor     string    `json:"actor"`
	Details   string    `json:"details"`
	Severity  string    `json:"severity"`
}

type BlockEntry struct {
	ID         string    `json:"id"`
	TargetType string    `json:"target_type"`
	TargetName string    `json:"target_name"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"created_at"`
}

type AllowEntry struct {
	ID         string    `json:"id"`
	TargetType string    `json:"target_type"`
	TargetName string    `json:"target_name"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"created_at"`
}

type Store struct {
	db *sql.DB
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("audit: open db %s: %w", dbPath, err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("audit: set WAL mode: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_events (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL,
		action TEXT NOT NULL,
		target TEXT,
		actor TEXT NOT NULL DEFAULT 'defenseclaw',
		details TEXT,
		severity TEXT
	);

	CREATE TABLE IF NOT EXISTS scan_results (
		id TEXT PRIMARY KEY,
		scanner TEXT NOT NULL,
		target TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		duration_ms INTEGER,
		finding_count INTEGER,
		max_severity TEXT,
		raw_json TEXT
	);

	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		scan_id TEXT NOT NULL,
		severity TEXT NOT NULL,
		title TEXT NOT NULL,
		description TEXT,
		location TEXT,
		remediation TEXT,
		scanner TEXT NOT NULL,
		tags TEXT,
		FOREIGN KEY (scan_id) REFERENCES scan_results(id)
	);

	CREATE TABLE IF NOT EXISTS block_list (
		id TEXT PRIMARY KEY,
		target_type TEXT NOT NULL,
		target_name TEXT NOT NULL,
		reason TEXT,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS allow_list (
		id TEXT PRIMARY KEY,
		target_type TEXT NOT NULL,
		target_name TEXT NOT NULL,
		reason TEXT,
		created_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
	CREATE INDEX IF NOT EXISTS idx_scan_scanner ON scan_results(scanner);
	CREATE INDEX IF NOT EXISTS idx_finding_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_finding_scan ON findings(scan_id);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_block_type_name ON block_list(target_type, target_name);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_allow_type_name ON allow_list(target_type, target_name);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("audit: init schema: %w", err)
	}
	return nil
}

// --- Audit Events ---

func (s *Store) LogEvent(e Event) error {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	if e.Actor == "" {
		e.Actor = "defenseclaw"
	}

	_, err := s.db.Exec(
		`INSERT INTO audit_events (id, timestamp, action, target, actor, details, severity)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.Timestamp, e.Action, e.Target, e.Actor, e.Details, e.Severity,
	)
	if err != nil {
		return fmt.Errorf("audit: log event: %w", err)
	}
	return nil
}

func (s *Store) InsertScanResult(id, scannerName, target string, ts time.Time, durationMs int64, findingCount int, maxSeverity, rawJSON string) error {
	_, err := s.db.Exec(
		`INSERT INTO scan_results (id, scanner, target, timestamp, duration_ms, finding_count, max_severity, raw_json)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, scannerName, target, ts, durationMs, findingCount, maxSeverity, rawJSON,
	)
	if err != nil {
		return fmt.Errorf("audit: insert scan result: %w", err)
	}
	return nil
}

func (s *Store) InsertFinding(id, scanID, severity, title, description, location, remediation, scannerName, tags string) error {
	_, err := s.db.Exec(
		`INSERT INTO findings (id, scan_id, severity, title, description, location, remediation, scanner, tags)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, scanID, severity, title, description, location, remediation, scannerName, tags,
	)
	if err != nil {
		return fmt.Errorf("audit: insert finding: %w", err)
	}
	return nil
}

func (s *Store) ListEvents(limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.Query(
		`SELECT id, timestamp, action, target, actor, details, severity
		 FROM audit_events ORDER BY timestamp DESC LIMIT ?`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var target, details, severity sql.NullString
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.Action, &target, &e.Actor, &details, &severity); err != nil {
			return nil, fmt.Errorf("audit: scan row: %w", err)
		}
		e.Target = target.String
		e.Details = details.String
		e.Severity = severity.String
		events = append(events, e)
	}
	return events, rows.Err()
}

// --- Block List ---

func (s *Store) AddBlock(targetType, targetName, reason string) error {
	id := uuid.New().String()
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO block_list (id, target_type, target_name, reason, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, targetType, targetName, reason, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("audit: add block: %w", err)
	}
	return nil
}

func (s *Store) RemoveBlock(targetType, targetName string) error {
	_, err := s.db.Exec(
		`DELETE FROM block_list WHERE target_type = ? AND target_name = ?`,
		targetType, targetName,
	)
	if err != nil {
		return fmt.Errorf("audit: remove block: %w", err)
	}
	return nil
}

func (s *Store) IsBlocked(targetType, targetName string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM block_list WHERE target_type = ? AND target_name = ?`,
		targetType, targetName,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("audit: check block: %w", err)
	}
	return count > 0, nil
}

func (s *Store) ListBlocked() ([]BlockEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, target_type, target_name, reason, created_at
		 FROM block_list ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list blocked: %w", err)
	}
	defer rows.Close()

	var entries []BlockEntry
	for rows.Next() {
		var e BlockEntry
		var reason sql.NullString
		if err := rows.Scan(&e.ID, &e.TargetType, &e.TargetName, &reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan block row: %w", err)
		}
		e.Reason = reason.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// --- Allow List ---

func (s *Store) AddAllow(targetType, targetName, reason string) error {
	id := uuid.New().String()
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO allow_list (id, target_type, target_name, reason, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, targetType, targetName, reason, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("audit: add allow: %w", err)
	}
	return nil
}

func (s *Store) RemoveAllow(targetType, targetName string) error {
	_, err := s.db.Exec(
		`DELETE FROM allow_list WHERE target_type = ? AND target_name = ?`,
		targetType, targetName,
	)
	if err != nil {
		return fmt.Errorf("audit: remove allow: %w", err)
	}
	return nil
}

func (s *Store) IsAllowed(targetType, targetName string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		`SELECT COUNT(*) FROM allow_list WHERE target_type = ? AND target_name = ?`,
		targetType, targetName,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("audit: check allow: %w", err)
	}
	return count > 0, nil
}

func (s *Store) ListAllowed() ([]AllowEntry, error) {
	rows, err := s.db.Query(
		`SELECT id, target_type, target_name, reason, created_at
		 FROM allow_list ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("audit: list allowed: %w", err)
	}
	defer rows.Close()

	var entries []AllowEntry
	for rows.Next() {
		var e AllowEntry
		var reason sql.NullString
		if err := rows.Scan(&e.ID, &e.TargetType, &e.TargetName, &reason, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("audit: scan allow row: %w", err)
		}
		e.Reason = reason.String
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

func (s *Store) Close() error {
	return s.db.Close()
}
