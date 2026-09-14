CREATE TABLE IF NOT EXISTS assessments (
  id SERIAL PRIMARY KEY,
  assessment_id VARCHAR(128) UNIQUE NOT NULL,
  name VARCHAR(255) NOT NULL,
  framework VARCHAR(64),
  status VARCHAR(32) NOT NULL DEFAULT 'planned',
  owner VARCHAR(255) NOT NULL,
  description TEXT,
  starts_at TIMESTAMPTZ,
  ends_at TIMESTAMPTZ,
  created_by VARCHAR(128) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  CONSTRAINT ck_assessments_status CHECK (
    status IN ('planned', 'in_progress', 'completed', 'closed', 'cancelled')
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_assessments_assessment_id
  ON assessments (assessment_id);
CREATE INDEX IF NOT EXISTS ix_assessments_framework
  ON assessments (framework);
CREATE INDEX IF NOT EXISTS ix_assessments_status
  ON assessments (status);

CREATE TABLE IF NOT EXISTS assessment_evidence (
  id SERIAL PRIMARY KEY,
  assessment_id VARCHAR(128) NOT NULL,
  evidence_id VARCHAR(128) NOT NULL,
  linked_by VARCHAR(128) NOT NULL,
  rationale TEXT,
  linked_at TIMESTAMPTZ DEFAULT now(),
  CONSTRAINT uq_assessment_evidence_pair UNIQUE (assessment_id, evidence_id),
  CONSTRAINT fk_assessment_evidence_assessment
    FOREIGN KEY (assessment_id) REFERENCES assessments (assessment_id) ON DELETE RESTRICT,
  CONSTRAINT fk_assessment_evidence_evidence
    FOREIGN KEY (evidence_id) REFERENCES evidence (evidence_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS ix_assessment_evidence_assessment_id
  ON assessment_evidence (assessment_id);
CREATE INDEX IF NOT EXISTS ix_assessment_evidence_evidence_id
  ON assessment_evidence (evidence_id);
