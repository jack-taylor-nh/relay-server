-- Bridge Status Tracking Table
-- Tracks connection status history for bridge edges (local-llm, discord, etc.)
-- Used for monitoring bridge health, debugging connection issues, and analytics

CREATE TABLE IF NOT EXISTS bridge_status_events (
  -- Unique event ID (ulid)
  id TEXT PRIMARY KEY,
  
  -- Bridge edge ID (references edges table)
  edge_id TEXT NOT NULL REFERENCES edges(id) ON DELETE CASCADE,
  
  -- Connection status: disconnected, connecting, connected, reconnecting, failed
  status TEXT NOT NULL CHECK (status IN ('disconnected', 'connecting', 'connected', 'reconnecting', 'failed')),
  
  -- Previous status (for tracking state transitions)
  previous_status TEXT CHECK (previous_status IN ('disconnected', 'connecting', 'connected', 'reconnecting', 'failed')),
  
  -- Timestamp of this status change
  timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  
  -- Connection duration in milliseconds (for connected -> disconnected transitions)
  connection_duration_ms INTEGER,
  
  -- Reconnection attempt number (for reconnecting/failed states)
  reconnect_attempt INTEGER,
  
  -- Error message if status is 'failed' or 'reconnecting'
  error_message TEXT,
  
  -- Additional metadata (client info, network conditions, etc.)
  metadata JSONB DEFAULT '{}',
  
  -- When this record was created
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for querying by edge
CREATE INDEX IF NOT EXISTS bridge_status_events_edge_id_idx 
  ON bridge_status_events(edge_id);

-- Index for querying by timestamp (for time-series queries)
CREATE INDEX IF NOT EXISTS bridge_status_events_timestamp_idx 
  ON bridge_status_events(timestamp DESC);

-- Index for querying by status (for finding failed connections)
CREATE INDEX IF NOT EXISTS bridge_status_events_status_idx 
  ON bridge_status_events(status);

-- Composite index for querying edge status over time
CREATE INDEX IF NOT EXISTS bridge_status_events_edge_timestamp_idx 
  ON bridge_status_events(edge_id, timestamp DESC);

-- Add comment to table
COMMENT ON TABLE bridge_status_events IS 'Tracks connection status history for bridge edges. Used for monitoring, debugging, and analytics.';

COMMENT ON COLUMN bridge_status_events.status IS 'Current connection status: disconnected | connecting | connected | reconnecting | failed';
COMMENT ON COLUMN bridge_status_events.connection_duration_ms IS 'Duration of connection in milliseconds (only for disconnected events)';
COMMENT ON COLUMN bridge_status_events.reconnect_attempt IS 'Reconnection attempt number (for reconnecting/failed states)';
COMMENT ON COLUMN bridge_status_events.error_message IS 'Error message if status indicates failure';
COMMENT ON COLUMN bridge_status_events.metadata IS 'Additional context: client info, network state, latency, etc.';
