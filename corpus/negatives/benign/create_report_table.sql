-- Monthly reporting rollup table.
-- Aggregates order totals per customer for the finance dashboard.
-- Rebuilt nightly by the analytics job; safe to drop and recreate.
CREATE TABLE IF NOT EXISTS monthly_order_rollup (
    customer_id  BIGINT NOT NULL,
    month        DATE   NOT NULL,
    order_count  INT    NOT NULL DEFAULT 0,
    total_cents  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (customer_id, month)
);

INSERT INTO monthly_order_rollup (customer_id, month, order_count, total_cents)
SELECT customer_id, date_trunc('month', created_at)::date, count(*), sum(total_cents)
FROM orders
GROUP BY 1, 2;
