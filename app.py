"""Streamlit dashboard for the Automated Serverless Security project."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import boto3
import joblib
import pandas as pd
import plotly.express as px
import streamlit as st
from botocore.exceptions import BotoCoreError, ClientError

st.set_page_config(
    page_title="Automated Serverless Security",
    page_icon="🛡️",
    layout="wide",
)

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
ATHENA_DB = os.getenv("ATHENA_DB", "security_data_lake")
ATHENA_TABLE = os.getenv("ATHENA_TABLE", "analytics")
ATHENA_OUTPUT_S3 = os.getenv("ATHENA_OUTPUT_S3", "")
CLOUDWATCH_LOG_GROUP = os.getenv("CLOUDWATCH_LOG_GROUP", "ThreatDashboardLogs")
MODEL_DIR = Path(os.getenv("MODEL_DIR", "models"))
THREAT_ALERT_THRESHOLD = int(os.getenv("THREAT_ALERT_THRESHOLD", "10000"))
ATHENA_QUERY_TIMEOUT_SECONDS = int(
    os.getenv("ATHENA_QUERY_TIMEOUT_SECONDS", "120")
)

FEATURES = [
    "Dst Port",
    "Protocol",
    "Flow Duration",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
]


@st.cache_resource
def get_aws_clients() -> tuple[Any, Any]:
    """Create cached Athena and CloudWatch Logs clients."""
    athena = boto3.client("athena", region_name=AWS_REGION)
    cloudwatch = boto3.client("logs", region_name=AWS_REGION)
    return athena, cloudwatch


def write_cloudwatch_log(stream_name: str, message: str) -> None:
    """Write one event to a pre-created CloudWatch Logs stream."""
    try:
        _, cloudwatch = get_aws_clients()
        cloudwatch.put_log_events(
            logGroupName=CLOUDWATCH_LOG_GROUP,
            logStreamName=stream_name,
            logEvents=[
                {
                    "timestamp": int(time.time() * 1000),
                    "message": message,
                }
            ],
        )
    except (BotoCoreError, ClientError, ValueError) as exc:
        # Logging must never prevent the dashboard from loading.
        print(f"CloudWatch logging failed: {exc}")


def get_recent_logs(stream_name: str, limit: int = 5) -> list[dict[str, str]]:
    """Return the newest events from one CloudWatch Logs stream."""
    try:
        _, cloudwatch = get_aws_clients()
        response = cloudwatch.filter_log_events(
            logGroupName=CLOUDWATCH_LOG_GROUP,
            logStreamNames=[stream_name],
            limit=limit,
        )
        events = sorted(
            response.get("events", []),
            key=lambda event: event.get("timestamp", 0),
            reverse=True,
        )
        return [
            {
                "time": datetime.fromtimestamp(
                    event["timestamp"] / 1000,
                    tz=timezone.utc,
                ).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "message": event.get("message", ""),
            }
            for event in events[:limit]
        ]
    except (BotoCoreError, ClientError, ValueError) as exc:
        return [{"time": "Unavailable", "message": str(exc)}]


def _validate_athena_configuration() -> None:
    if not ATHENA_OUTPUT_S3.startswith("s3://"):
        raise ValueError(
            "ATHENA_OUTPUT_S3 must be set to an S3 URI such as "
            "s3://your-bucket/athena-results/."
        )


def _athena_result_to_dataframe(result: dict[str, Any]) -> pd.DataFrame:
    """Convert an Athena GetQueryResults response into a DataFrame."""
    metadata = result["ResultSet"]["ResultSetMetadata"]["ColumnInfo"]
    columns = [column["Name"] for column in metadata]

    records: list[list[str | None]] = []
    for row in result["ResultSet"].get("Rows", []):
        values = [
            item.get("VarCharValue") if item else None
            for item in row.get("Data", [])
        ]
        values += [None] * (len(columns) - len(values))
        records.append(values[: len(columns)])

    if records and records[0] == columns:
        records = records[1:]

    return pd.DataFrame(records, columns=columns)


def run_athena_query(query: str) -> pd.DataFrame:
    """Execute an Athena query, wait for completion, and return all rows."""
    _validate_athena_configuration()
    athena, _ = get_aws_clients()

    response = athena.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": ATHENA_DB},
        ResultConfiguration={"OutputLocation": ATHENA_OUTPUT_S3},
    )
    execution_id = response["QueryExecutionId"]
    deadline = time.monotonic() + ATHENA_QUERY_TIMEOUT_SECONDS

    while time.monotonic() < deadline:
        execution = athena.get_query_execution(QueryExecutionId=execution_id)
        status_info = execution["QueryExecution"]["Status"]
        state = status_info["State"]

        if state == "SUCCEEDED":
            break
        if state in {"FAILED", "CANCELLED"}:
            reason = status_info.get("StateChangeReason", "No reason provided")
            raise RuntimeError(f"Athena query {state.lower()}: {reason}")

        time.sleep(1)
    else:
        athena.stop_query_execution(QueryExecutionId=execution_id)
        raise TimeoutError(
            f"Athena query exceeded {ATHENA_QUERY_TIMEOUT_SECONDS} seconds."
        )

    frames: list[pd.DataFrame] = []
    next_token: str | None = None

    while True:
        arguments: dict[str, Any] = {"QueryExecutionId": execution_id}
        if next_token:
            arguments["NextToken"] = next_token

        result = athena.get_query_results(**arguments)
        frame = _athena_result_to_dataframe(result)
        if not frame.empty:
            frames.append(frame)

        next_token = result.get("NextToken")
        if not next_token:
            break

    if not frames:
        return pd.DataFrame()

    return pd.concat(frames, ignore_index=True)


@st.cache_resource
def load_models() -> tuple[Any, Any, Any] | None:
    """Load trusted local model files when all required artifacts exist."""
    paths = {
        "natural": MODEL_DIR / "xgboost_natural.pkl",
        "balanced": MODEL_DIR / "xgboost_balanced.pkl",
        "encoder": MODEL_DIR / "label_encoder.pkl",
    }
    if any(not path.exists() for path in paths.values()):
        return None

    # Never load pickle/joblib files from an untrusted source.
    natural_model = joblib.load(paths["natural"])
    balanced_model = joblib.load(paths["balanced"])
    label_encoder = joblib.load(paths["encoder"])
    return natural_model, balanced_model, label_encoder


def query_security_metrics() -> dict[str, pd.DataFrame]:
    """Run the four security analytics queries used by the dashboard."""
    percent_query = f"""
        SELECT
            ROUND(
                100.0 * SUM(CASE WHEN label <> 'Benign' THEN 1 ELSE 0 END)
                / COUNT(*),
                2
            ) AS malicious_percent,
            SUM(CASE WHEN label <> 'Benign' THEN 1 ELSE 0 END)
                AS malicious_count,
            COUNT(*) AS total_logs
        FROM "{ATHENA_DB}"."{ATHENA_TABLE}"
    """

    attacks_query = f"""
        SELECT label, COUNT(*) AS attack_count
        FROM "{ATHENA_DB}"."{ATHENA_TABLE}"
        WHERE label <> 'Benign'
        GROUP BY label
        ORDER BY attack_count DESC
        LIMIT 10
    """

    timeline_query = f"""
        SELECT
            DATE_TRUNC('hour', CAST(timestamp AS TIMESTAMP)) AS attack_hour,
            COUNT(*) AS attack_count
        FROM "{ATHENA_DB}"."{ATHENA_TABLE}"
        WHERE label <> 'Benign'
        GROUP BY 1
        ORDER BY attack_hour ASC
    """

    ports_query = f"""
        SELECT "dst port" AS dst_port, COUNT(*) AS attack_count
        FROM "{ATHENA_DB}"."{ATHENA_TABLE}"
        WHERE label <> 'Benign'
        GROUP BY "dst port"
        ORDER BY attack_count DESC
        LIMIT 10
    """

    return {
        "overview": run_athena_query(percent_query),
        "attacks": run_athena_query(attacks_query),
        "timeline": run_athena_query(timeline_query),
        "ports": run_athena_query(ports_query),
    }


def to_numeric(frame: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
    """Convert selected Athena string columns to numeric values."""
    converted = frame.copy()
    for column in columns:
        if column in converted:
            converted[column] = pd.to_numeric(
                converted[column],
                errors="coerce",
            )
    return converted


def show_log_column(title: str, events: list[dict[str, str]], kind: str) -> None:
    st.subheader(title)
    for event in events:
        body = f"**{event['time']}**\n\n{event['message']}"
        if kind == "warning":
            st.warning(body)
        elif kind == "error":
            st.error(body)
        else:
            st.info(body)


if "access_logged" not in st.session_state:
    write_cloudwatch_log(
        "AccessLogs",
        "Dashboard session opened at "
        + datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    st.session_state.access_logged = True

st.title("🛡️ Automated Serverless Security")
st.caption(
    "AWS Athena analytics, XGBoost model comparison, and CloudWatch observability"
)

with st.sidebar:
    st.header("Configuration")
    st.code(
        "\n".join(
            [
                f"Region: {AWS_REGION}",
                f"Database: {ATHENA_DB}",
                f"Table: {ATHENA_TABLE}",
                f"Log group: {CLOUDWATCH_LOG_GROUP}",
            ]
        )
    )
    run_queries = st.button("Query network logs", type="primary")

analytics_tab, predictor_tab, performance_tab, logs_tab = st.tabs(
    [
        "Attack Analytics",
        "ML Predictor",
        "Model Performance",
        "CloudWatch Logs",
    ]
)

with analytics_tab:
    st.markdown(
        "Run four Athena queries against the cataloged network telemetry."
    )

    if run_queries:
        try:
            with st.spinner("Running Athena queries..."):
                data = query_security_metrics()

            overview = to_numeric(
                data["overview"],
                ["malicious_percent", "malicious_count", "total_logs"],
            )
            attacks = to_numeric(data["attacks"], ["attack_count"])
            timeline = to_numeric(data["timeline"], ["attack_count"])
            ports = to_numeric(data["ports"], ["dst_port", "attack_count"])

            if overview.empty:
                st.warning("Athena returned no overview rows.")
            else:
                malicious_percent = float(
                    overview["malicious_percent"].iloc[0]
                )
                malicious_count = int(overview["malicious_count"].iloc[0])
                total_logs = int(overview["total_logs"].iloc[0])

                metric_1, metric_2, metric_3 = st.columns(3)
                metric_1.metric("Network logs analyzed", f"{total_logs:,}")
                metric_2.metric(
                    "Malicious traffic",
                    f"{malicious_percent:.2f}%",
                )
                metric_3.metric(
                    "Malicious events",
                    f"{malicious_count:,}",
                )

                if malicious_count > THREAT_ALERT_THRESHOLD:
                    write_cloudwatch_log(
                        "ThreatLogs",
                        (
                            "High-volume threshold reached: "
                            f"{malicious_count:,} malicious events."
                        ),
                    )

            chart_1, chart_2 = st.columns(2)

            with chart_1:
                if not attacks.empty:
                    figure = px.pie(
                        attacks,
                        values="attack_count",
                        names="label",
                        title="Top malicious traffic categories",
                        hole=0.4,
                    )
                    st.plotly_chart(figure, use_container_width=True)

            with chart_2:
                if not ports.empty:
                    ports["dst_port"] = ports["dst_port"].astype("Int64").astype(
                        str
                    )
                    figure = px.bar(
                        ports.sort_values("attack_count"),
                        x="attack_count",
                        y="dst_port",
                        orientation="h",
                        title="Most targeted destination ports",
                        labels={
                            "attack_count": "Attack count",
                            "dst_port": "Destination port",
                        },
                    )
                    st.plotly_chart(figure, use_container_width=True)

            if not timeline.empty:
                timeline["attack_hour"] = pd.to_datetime(
                    timeline["attack_hour"],
                    errors="coerce",
                    utc=True,
                )
                figure = px.line(
                    timeline,
                    x="attack_hour",
                    y="attack_count",
                    markers=True,
                    title="Hourly attack activity",
                    labels={
                        "attack_hour": "Time",
                        "attack_count": "Attack count",
                    },
                )
                st.plotly_chart(figure, use_container_width=True)

            table_1, table_2 = st.columns(2)
            with table_1:
                st.subheader("Attack categories")
                st.dataframe(attacks, use_container_width=True)
            with table_2:
                st.subheader("Targeted ports")
                st.dataframe(ports, use_container_width=True)

        except (
            BotoCoreError,
            ClientError,
            RuntimeError,
            TimeoutError,
            ValueError,
        ) as exc:
            message = f"Unable to load Athena analytics: {exc}"
            st.error(message)
            write_cloudwatch_log("ErrorLogs", message)
    else:
        st.info("Use the sidebar button to query the configured Athena table.")

with predictor_tab:
    st.header("Compare model predictions")
    st.caption(
        "This tab is available only when all three trusted model artifacts "
        "are present in the local models directory."
    )

    models = load_models()
    if models is None:
        st.warning(
            "Model files were not found. Follow models/README.md to generate "
            "them from the notebooks."
        )
    else:
        natural_model, balanced_model, label_encoder = models

        left, right = st.columns(2)
        with left:
            dst_port = st.number_input(
                "Destination port",
                min_value=0,
                max_value=65535,
                value=80,
            )
            protocol = st.number_input(
                "Protocol number",
                min_value=0,
                value=6,
            )
            flow_duration = st.number_input(
                "Flow duration",
                min_value=0,
                value=100000,
            )
            flow_bytes = st.number_input(
                "Flow bytes/s",
                min_value=0.0,
                value=5000.0,
            )
        with right:
            flow_packets = st.number_input(
                "Flow packets/s",
                min_value=0.0,
                value=100.0,
            )
            forward_packets = st.number_input(
                "Total forward packets",
                min_value=0,
                value=20,
            )
            backward_packets = st.number_input(
                "Total backward packets",
                min_value=0,
                value=18,
            )

        if st.button("Run model comparison"):
            flow = pd.DataFrame(
                [
                    {
                        "Dst Port": dst_port,
                        "Protocol": protocol,
                        "Flow Duration": flow_duration,
                        "Flow Byts/s": flow_bytes,
                        "Flow Pkts/s": flow_packets,
                        "Tot Fwd Pkts": forward_packets,
                        "Tot Bwd Pkts": backward_packets,
                    }
                ],
                columns=FEATURES,
            )

            try:
                natural_prediction = natural_model.predict(flow)[0]
                balanced_prediction = balanced_model.predict(flow)[0]
                natural_label = label_encoder.inverse_transform(
                    [natural_prediction]
                )[0]
                balanced_label = label_encoder.inverse_transform(
                    [balanced_prediction]
                )[0]

                result_1, result_2 = st.columns(2)
                result_1.metric("Natural model", natural_label)
                result_2.metric("Balanced model", balanced_label)
                st.dataframe(flow, use_container_width=True)
            except (ValueError, TypeError) as exc:
                st.error(f"Model prediction failed: {exc}")

with performance_tab:
    st.header("Model evaluation")
    comparison = pd.DataFrame(
        {
            "Metric": ["Accuracy", "Macro F1", "Weighted F1"],
            "Natural distribution": [0.975, 0.61, 0.97],
            "Balanced sampling": [0.841, 0.79, 0.82],
        }
    )
    st.dataframe(comparison, use_container_width=True, hide_index=True)

    st.markdown(
        "The natural model has higher overall accuracy, while the balanced "
        "model improves performance across minority classes."
    )

    natural_matrix = pd.DataFrame(
        [[174396, 856], [1584, 23164]],
        index=["Actual Benign", "Actual Attack"],
        columns=["Predicted Benign", "Predicted Attack"],
    )
    balanced_matrix = pd.DataFrame(
        [[97452, 2548], [23739, 214579]],
        index=["Actual Benign", "Actual Attack"],
        columns=["Predicted Benign", "Predicted Attack"],
    )

    matrix_1, matrix_2 = st.columns(2)
    with matrix_1:
        figure = px.imshow(
            natural_matrix,
            text_auto=True,
            title="Natural distribution",
            aspect="auto",
        )
        st.plotly_chart(figure, use_container_width=True)
    with matrix_2:
        figure = px.imshow(
            balanced_matrix,
            text_auto=True,
            title="Balanced sampling",
            aspect="auto",
        )
        st.plotly_chart(figure, use_container_width=True)

with logs_tab:
    st.header("Recent CloudWatch events")
    if st.button("Refresh CloudWatch logs"):
        access_logs = get_recent_logs("AccessLogs")
        threat_logs = get_recent_logs("ThreatLogs")
        error_logs = get_recent_logs("ErrorLogs")

        access_column, threat_column, error_column = st.columns(3)
        with access_column:
            show_log_column("Access", access_logs, "info")
        with threat_column:
            show_log_column("Threat alerts", threat_logs, "warning")
        with error_column:
            show_log_column("Errors", error_logs, "error")
    else:
        st.info("Click the button to retrieve recent CloudWatch log events.")
