# AWS Setup Guide

This guide is a cleaned and security-focused version of the original class lab.

## Before you begin

You need:

- An AWS account or AWS Academy learner environment
- Permission to use S3, Glue, Athena, CloudWatch Logs, and an execution environment
- AWS CLI and Python 3.10 or later
- Network telemetry files in CSV or Parquet format

> The original lab used AWS Cloud9. [AWS states that Cloud9 is no longer available to new customers](https://docs.aws.amazon.com/cloud9/latest/APIReference/Welcome.html); existing Cloud9 customers can continue to use it. New users can run this project from local VS Code, AWS CloudShell for CLI tasks, or an EC2 development instance.

## 1. Create the S3 data lake

Create a globally unique bucket such as:

```text
security-data-lake-<unique-suffix>
```

Recommended settings:

- General purpose bucket
- Object Ownership: Bucket owner enforced
- Block all public access: enabled
- Default encryption: SSE-S3 or SSE-KMS
- Versioning: optional for a class lab; recommended when recovery is important

Create these prefixes:

```text
analytics/
athena-results/
models/
```

Upload the extracted telemetry files under `analytics/`.

Do not upload credentials, private data, or source files you do not have permission to share.

## 2. Create the Glue Data Catalog table

1. Open AWS Glue.
2. Create a crawler named `network-logs-crawler`.
3. Use the S3 `analytics/` prefix as the data source.
4. Assign a Glue service role with read access to that prefix.
5. Create or select a database named `security_data_lake`.
6. Set the crawler schedule to **On demand**.
7. Run the crawler.
8. Confirm that the `analytics` table appears in the Data Catalog.

In AWS Academy, an existing lab role may be provided. Outside the academy environment, create a dedicated role instead of assuming a role named `LabRole`.

## 3. Configure Athena

1. Open Athena Query Editor.
2. Set the query-result location to:

```text
s3://YOUR-BUCKET/athena-results/
```

3. Select:
   - Data source: `AwsDataCatalog`
   - Database: `security_data_lake`
4. Confirm the `analytics` table is available.
5. Run the queries in [`queries/security_queries.sql`](../queries/security_queries.sql).

## 4. Create CloudWatch log resources

```bash
aws logs create-log-group \
  --log-group-name ThreatDashboardLogs \
  --region us-east-1

for stream in AccessLogs ErrorLogs ThreatLogs; do
  aws logs create-log-stream \
    --log-group-name ThreatDashboardLogs \
    --log-stream-name "$stream" \
    --region us-east-1
done
```

The application writes three categories:

- `AccessLogs`: dashboard session access
- `ErrorLogs`: application or AWS query failures
- `ThreatLogs`: threshold-based high-volume alerts

## 5. Configure local environment variables

```bash
export AWS_REGION=us-east-1
export ATHENA_DB=security_data_lake
export ATHENA_TABLE=analytics
export ATHENA_OUTPUT_S3=s3://YOUR-BUCKET/athena-results/
export CLOUDWATCH_LOG_GROUP=ThreatDashboardLogs
export THREAT_ALERT_THRESHOLD=10000
```

Use an IAM role, IAM Identity Center, or an AWS CLI profile. Never place access keys in source code.

## 6. Prepare model artifacts

Run the notebooks to produce:

```text
models/xgboost_natural.pkl
models/xgboost_balanced.pkl
models/label_encoder.pkl
```

Only load model files that you created yourself or obtained from a trusted source. See [`models/README.md`](../models/README.md).

## 7. Install and run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## Suggested IAM permissions

Use separate roles where practical.

The dashboard needs only the actions required for:

- Athena query execution and result retrieval
- Read/write access to the Athena results prefix
- Read access to the cataloged source data through Athena
- Writing and reading the named CloudWatch log group

Avoid broad permissions such as `AdministratorAccess` for a portfolio deployment.

## Cleanup

To avoid continuing charges:

- Stop or terminate EC2 development instances
- Delete unnecessary Athena result objects
- Remove unused Glue crawlers and tables
- Delete CloudWatch log groups when no longer needed
- Empty and delete the S3 bucket when the lab is complete
