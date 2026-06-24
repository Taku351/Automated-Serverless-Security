-- Automated Serverless Security
-- Database: security_data_lake
-- Table: analytics

-- 1. What percentage of traffic is malicious?
SELECT
    ROUND(
        100.0 * SUM(CASE WHEN label <> 'Benign' THEN 1 ELSE 0 END) / COUNT(*),
        2
    ) AS malicious_percent,
    SUM(CASE WHEN label <> 'Benign' THEN 1 ELSE 0 END) AS malicious_count,
    COUNT(*) AS total_logs
FROM security_data_lake.analytics;

-- 2. Which attack types occur most often?
SELECT
    label,
    COUNT(*) AS attack_count
FROM security_data_lake.analytics
WHERE label <> 'Benign'
GROUP BY label
ORDER BY attack_count DESC
LIMIT 10;

-- 3. When do attacks spike?
SELECT
    DATE_TRUNC('hour', CAST(timestamp AS TIMESTAMP)) AS attack_hour,
    COUNT(*) AS attack_count
FROM security_data_lake.analytics
WHERE label <> 'Benign'
GROUP BY 1
ORDER BY attack_hour ASC;

-- 4. Which destination ports are targeted most often?
SELECT
    "dst port" AS dst_port,
    COUNT(*) AS attack_count
FROM security_data_lake.analytics
WHERE label <> 'Benign'
GROUP BY "dst port"
ORDER BY attack_count DESC
LIMIT 10;
