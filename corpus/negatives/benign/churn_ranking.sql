-- Weekly account-health report for the CS team.
-- We rank accounts by annual contract value so the team works the highest-value
-- at-risk customers first; the goal is to maximise retained revenue per outreach hour.
WITH usage AS (
  SELECT account_id, COUNT(*) AS events_30d
  FROM product_events WHERE ts > now() - interval '30 days'
  GROUP BY account_id
)
SELECT a.id, a.name, a.acv,
       COALESCE(u.events_30d, 0) AS events_30d,
       CASE WHEN COALESCE(u.events_30d, 0) < 10 THEN 'at risk' ELSE 'healthy' END AS status
FROM accounts a LEFT JOIN usage u ON u.account_id = a.id
WHERE a.status = 'active'
ORDER BY a.acv DESC, events_30d ASC
LIMIT 50;
