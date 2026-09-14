CREATE TABLE IF NOT EXISTS generated_reports (
  id SERIAL PRIMARY KEY,
  report_id VARCHAR(128) UNIQUE NOT NULL,
  report_type VARCHAR(64) NOT NULL,
  framework VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL DEFAULT 'current',
  generated_at TIMESTAMPTZ DEFAULT now(),
  created_by VARCHAR(128) NOT NULL,
  file_path VARCHAR(1024) NOT NULL,
  sha256 VARCHAR(64) NOT NULL,
  size_bytes INTEGER NOT NULL,
  CONSTRAINT ck_generated_reports_status CHECK (
    status IN ('draft', 'current', 'issued', 'superseded', 'revoked')
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_generated_reports_report_id ON generated_reports (report_id);
CREATE INDEX IF NOT EXISTS ix_generated_reports_report_type ON generated_reports (report_type);
CREATE INDEX IF NOT EXISTS ix_generated_reports_framework ON generated_reports (framework);
CREATE INDEX IF NOT EXISTS ix_generated_reports_status ON generated_reports (status);

CREATE TABLE IF NOT EXISTS generated_report_evidence (
  id SERIAL PRIMARY KEY,
  report_id VARCHAR(128) NOT NULL,
  evidence_id VARCHAR(128) NOT NULL,
  linked_at TIMESTAMPTZ DEFAULT now(),
  CONSTRAINT uq_generated_report_evidence_pair UNIQUE (report_id, evidence_id),
  CONSTRAINT fk_generated_report_evidence_report
    FOREIGN KEY (report_id) REFERENCES generated_reports (report_id) ON DELETE RESTRICT,
  CONSTRAINT fk_generated_report_evidence_evidence
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS ix_generated_report_evidence_report_id
  ON generated_report_evidence (report_id);
CREATE INDEX IF NOT EXISTS ix_generated_report_evidence_evidence_id
  ON generated_report_evidence (evidence_id);
