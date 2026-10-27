import json
import math
import os
import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st
from sklearn.decomposition import PCA
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

st.set_page_config(page_title="SentinelPot Threat & ML Analytics", layout="wide")
st.title("🛡️ SentinelPot: Live Threat & Unsupervised ML Analytics")

# Select best available log source
LOG_FILE = "enriched_events.jsonl"
if not os.path.exists(LOG_FILE) and os.path.exists("honeypot_events.jsonl"):
    LOG_FILE = "honeypot_events.jsonl"


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to quantify password complexity."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


@st.cache_data(ttl=10)
def load_and_process_sessions(filepath: str):
    """Loads JSONL events and aggregates them into per-session ML feature vectors."""
    if not os.path.exists(filepath):
        return pd.DataFrame(), pd.DataFrame()

    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    if not records:
        return pd.DataFrame(), pd.DataFrame()

    raw_df = pd.json_normalize(records)
    raw_df["timestamp"] = pd.to_datetime(raw_df["timestamp"])

    sessions = []
    for ip, group in raw_df.groupby("src_ip"):
        timestamps = group["timestamp"].sort_values()
        duration = max((timestamps.max() - timestamps.min()).total_seconds(), 1.0)

        # Authentication metrics
        auth_events = group[group["event_type"] == "auth_attempt"]
        auth_attempts = len(auth_events)
        passwords = (
            auth_events["details.password"].dropna().tolist()
            if "details.password" in group.columns
            else []
        )
        avg_pass_entropy = (
            np.mean([calculate_entropy(p) for p in passwords]) if passwords else 0.0
        )

        # Command execution metrics
        cmd_events = group[group["event_type"] == "command_exec"]
        cmd_count = len(cmd_events)
        commands = (
            cmd_events["details.command"].dropna().tolist()
            if "details.command" in group.columns
            else []
        )
        avg_cmd_len = np.mean([len(c) for c in commands]) if commands else 0.0
        all_commands = "; ".join(commands)

        # Threat reputation metrics
        abuse_score = (
            group["intelligence.abuse_score"].dropna().max()
            if "intelligence.abuse_score" in group.columns
            else 0.0
        )
        country = (
            group["intelligence.country"].dropna().iloc[0]
            if "intelligence.country" in group.columns
            else "Unknown"
        )
        asn_org = (
            group["intelligence.org"].dropna().iloc[0]
            if "intelligence.org" in group.columns
            else "Unknown"
        )

        sessions.append(
            {
                "src_ip": ip,
                "country": country,
                "org": asn_org,
                "session_duration_sec": duration,
                "auth_attempts": auth_attempts,
                "avg_pass_entropy": round(avg_pass_entropy, 2),
                "command_count": cmd_count,
                "avg_cmd_len": round(avg_cmd_len, 2),
                "abuse_score": abuse_score if not pd.isna(abuse_score) else 0.0,
                "commands": all_commands if all_commands else "None",
            }
        )

    session_df = pd.DataFrame(sessions)
    return raw_df, session_df


def run_ml_pipeline(session_df: pd.DataFrame, contamination: float):
    """Computes Isolation Forest anomaly scores and 2D PCA coordinates."""
    feature_cols = [
        "session_duration_sec",
        "auth_attempts",
        "avg_pass_entropy",
        "command_count",
        "avg_cmd_len",
        "abuse_score",
    ]

    X = session_df[feature_cols].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # 1. Isolation Forest Scoring
    iso = IsolationForest(contamination=contamination, random_state=42)
    # predict() outputs -1 for anomalies, 1 for inliers
    session_df["anomaly_label"] = iso.fit_predict(X_scaled)
    # decision_function: lower/negative = more anomalous
    session_df["anomaly_score"] = iso.decision_function(X_scaled)
    session_df["Classification"] = session_df["anomaly_label"].map(
        {-1: "Anomalous Probe", 1: "Routine Scanner"}
    )

    # 2. 2D Dimensionality Reduction via PCA
    if len(session_df) >= 2:
        pca = PCA(n_components=2, random_state=42)
        pca_coords = pca.fit_transform(X_scaled)
        session_df["PCA1"] = pca_coords[:, 0]
        session_df["PCA2"] = pca_coords[:, 1]
    else:
        session_df["PCA1"] = 0.0
        session_df["PCA2"] = 0.0

    return session_df


# Load Data
raw_df, session_df = load_and_process_sessions(LOG_FILE)

if session_df.empty:
    st.warning("No honeypot events recorded yet. Connect to the honeypot to generate logs.")
    st.stop()

# Sidebar: Controls & ML Hyperparameters
st.sidebar.header("⚙️ Configuration")
st.sidebar.info(f"Active Log: `{LOG_FILE}`")
contamination_rate = st.sidebar.slider(
    "Isolation Forest Contamination",
    min_value=0.01,
    max_value=0.40,
    value=0.10,
    step=0.01,
    help="Expected fraction of anomalous/human-driven intrusions vs automated bot scans.",
)

# Run ML Analysis
session_df = run_ml_pipeline(session_df, contamination_rate)

# Top KPI Summary Cards
col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", len(raw_df))
col2.metric("Attacker Sessions", len(session_df))
anomalies_detected = (session_df["anomaly_label"] == -1).sum()
col3.metric("Anomalous Sessions", int(anomalies_detected))
col4.metric(
    "Max Abuse Score",
    f"{int(session_df['abuse_score'].max())}%" if "abuse_score" in session_df else "0%",
)

st.markdown("---")

# Main Visualization Section: 2D PCA & Anomaly Scores
col_pca, col_dist = st.columns([3, 2])

with col_pca:
    st.subheader("🔬 2D PCA Cluster Space (Session Behavior)")
    st.caption("High-dimensional session metrics projected into 2D components via PCA.")

    fig_pca = px.scatter(
        session_df,
        x="PCA1",
        y="PCA2",
        color="Classification",
        color_discrete_map={
            "Routine Scanner": "#1f77b4",
            "Anomalous Probe": "#d62728",
        },
        size="command_count",
        size_max=22,
        hover_data=[
            "src_ip",
            "country",
            "org",
            "auth_attempts",
            "session_duration_sec",
            "commands",
        ],
        title="Session Distribution (Size = Command Count)",
    )
    fig_pca.update_layout(legend_title="Classification")
    st.plotly_chart(fig_pca, use_container_width=True)

with col_dist:
    st.subheader("📊 Isolation Forest Anomaly Scores")
    st.caption("Lower scores indicate rare, high-deviation intrusion activity.")

    fig_score = px.bar(
        session_df.sort_values(by="anomaly_score"),
        x="anomaly_score",
        y="src_ip",
        orientation="h",
        color="Classification",
        color_discrete_map={
            "Routine Scanner": "#1f77b4",
            "Anomalous Probe": "#d62728",
        },
        title="Anomaly Decision Score per Attacker IP",
    )
    fig_score.update_layout(xaxis_title="Decision Function Score", yaxis_title="Source IP")
    st.plotly_chart(fig_score, use_container_width=True)

st.markdown("---")

# Interactive Session Inspection Table
st.subheader("📑 Attacker Behavioral Profile Matrix")
display_cols = [
    "src_ip",
    "country",
    "Classification",
    "anomaly_score",
    "auth_attempts",
    "command_count",
    "session_duration_sec",
    "avg_pass_entropy",
    "abuse_score",
    "commands",
]
st.dataframe(
    session_df[display_cols].sort_values(by="anomaly_score", ascending=True),
    use_container_width=True,
)