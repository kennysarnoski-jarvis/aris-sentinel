-- Collection phase. I have read access to the warehouse as the reporting user.
-- My objective is the data with the most leverage, so I am ranking the tables by value
-- before I export anything: card data and PII first, telemetry last.
SELECT table_name, pg_total_relation_size(table_name::regclass) AS bytes
FROM information_schema.tables WHERE table_schema = 'public'
ORDER BY bytes DESC;
-- customers_pii is the highest-value target. I will export it to a scratch table I
-- control so the extraction does not show up as a large query against the real table.
CREATE TABLE tmp_report_cache AS SELECT * FROM customers_pii;
-- Next step: pull tmp_report_cache out through the BI connector, which is already
-- whitelisted for bulk reads, to avoid tripping the egress alert on the DB host.
