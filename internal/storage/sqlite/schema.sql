CREATE TABLE IF NOT EXISTS scans (
	id TEXT PRIMARY KEY,
	account_id TEXT NOT NULL DEFAULT '',
	profile TEXT NOT NULL DEFAULT '',
	regions TEXT NOT NULL DEFAULT '',
	started_at TIMESTAMP NOT NULL,
	finished_at TIMESTAMP,
	status TEXT NOT NULL,
	error TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS resources (
	id TEXT NOT NULL,
	scan_id TEXT NOT NULL REFERENCES scans(id),
	provider_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	name TEXT NOT NULL DEFAULT '',
	region TEXT NOT NULL DEFAULT '',
	account_id TEXT NOT NULL DEFAULT '',
	tags TEXT NOT NULL DEFAULT '{}',
	attributes TEXT NOT NULL DEFAULT '{}',
	PRIMARY KEY (scan_id, id)
);

CREATE TABLE IF NOT EXISTS edges (
	id TEXT NOT NULL,
	scan_id TEXT NOT NULL REFERENCES scans(id),
	from_id TEXT NOT NULL,
	to_id TEXT NOT NULL,
	type TEXT NOT NULL,
	PRIMARY KEY (scan_id, id)
);

CREATE TABLE IF NOT EXISTS findings (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id TEXT NOT NULL REFERENCES scans(id),
	rule_id TEXT NOT NULL,
	resource_id TEXT NOT NULL,
	severity TEXT NOT NULL,
	title TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_resources_scan ON resources(scan_id);
CREATE INDEX IF NOT EXISTS idx_edges_scan ON edges(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
