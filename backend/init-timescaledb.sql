-- TimescaleDB initialization for PhantomScan
-- Run as superuser (postgres) during container initialization

-- Create TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Create pgvector extension for AI embeddings
CREATE EXTENSION IF NOT EXISTS vector;

-- Create uuid-ossp for UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant privileges to phantomscan user
GRANT ALL PRIVILEGES ON DATABASE phantomscan TO phantomscan;
GRANT USAGE ON SCHEMA public TO phantomscan;
GRANT CREATE ON SCHEMA public TO phantomscan;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO phantomscan;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO phantomscan;