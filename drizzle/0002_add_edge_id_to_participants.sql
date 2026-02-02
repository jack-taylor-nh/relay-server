-- Add edge_id to conversation_participants for edge-to-edge messaging
-- This enables proper edge-based conversation lookups without identity joins

ALTER TABLE conversation_participants 
ADD COLUMN edge_id uuid REFERENCES edges(id);

-- Index for edge-based participant lookups
CREATE INDEX cp_edge_idx ON conversation_participants(edge_id);
