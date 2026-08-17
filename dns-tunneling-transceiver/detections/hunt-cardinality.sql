-- DNS Tunneling Transceiver - durable detection (level 2)
--
-- The signal that survives a rename. To move a byte out over DNS you must ask a
-- question the resolver has never seen, because a cache answers repeated questions and
-- exfil never repeats one. Every chunk is therefore a fresh cache miss and a recursive
-- lookup the resolver is obliged to record. This query keys on that structural fact -
-- unique-label cardinality and long, high-entropy labels per registered domain - not
-- on any constant the operator controls. Jitter, re-encoding and record-type swaps do
-- nothing to it.
--
-- The column names below are generic. Map them to your source:
--   * Pi-hole FTL  : the `queries` table in /etc/pihole/pihole-FTL.db (domain, timestamp)
--   * Unbound      : query log parsed into a table
--   * Zeek dns.log : `query`, `ts`, split off the registered domain (2LD/eTLD+1)
--
-- `registered_domain` = the eTLD+1 (e.g. exfil.lab.example -> lab.example, or your
-- registrable boundary). `subdomain` = everything to the left of it.

SELECT   registered_domain,
         COUNT(*)                    AS queries,
         COUNT(DISTINCT subdomain)   AS unique_labels,
         AVG(LENGTH(subdomain))      AS avg_label_len,
         MAX(LENGTH(subdomain))      AS max_label_len
FROM     dns_queries
WHERE    ts > now() - INTERVAL '5 minutes'
GROUP BY registered_domain
HAVING   COUNT(DISTINCT subdomain) > 100      -- climbing novel-label count
   AND   AVG(LENGTH(subdomain))    > 30        -- long, encoded labels
ORDER BY unique_labels DESC;

-- Tuning notes:
--   * Lower the unique_labels threshold for quieter, slower tunnels; the ratio of
--     unique labels to total queries approaching 1.0 is itself the tell.
--   * A high NXDOMAIN rate per registered_domain is corroborating when the tool uses
--     names with no real records; join your response-code field if you have it.
--   * Baseline-heavy CDNs (telemetry, analytics) can show high cardinality too -
--     allowlist known registrable domains, or compare against a 30-day per-domain
--     baseline rather than a fixed threshold.
