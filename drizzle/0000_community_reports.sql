CREATE TABLE reported_sites (
  id TEXT PRIMARY KEY NOT NULL,
  canonical_url TEXT NOT NULL,
  display_url TEXT NOT NULL,
  hostname TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'suplantacion',
  notes TEXT NOT NULL DEFAULT '',
  report_count INTEGER NOT NULL DEFAULT 1,
  alert_votes INTEGER NOT NULL DEFAULT 0,
  dispute_votes INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'community_reported',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_reported_sites_updated_at
ON reported_sites(updated_at DESC);

CREATE INDEX idx_reported_sites_hostname
ON reported_sites(hostname);

CREATE UNIQUE INDEX reported_sites_canonical_url_unique
ON reported_sites(canonical_url);
