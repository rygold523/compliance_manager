ALTER TABLE assets
ADD COLUMN IF NOT EXISTS asset_roles JSON DEFAULT '[]'::json;

ALTER TABLE assets
ADD COLUMN IF NOT EXISTS data_classification JSON DEFAULT '[]'::json;
