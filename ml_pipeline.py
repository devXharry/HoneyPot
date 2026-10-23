import json
import math
import os
import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler

SOURCE_LOG = "enriched_events.jsonl"
# Fallback to raw logs if enriched file doesn't exist yet
if not os.path.exists(SOURCE_LOG) and os.path.exists("honeypot_events.jsonl"):
    SOURCE_LOG = "honeypot_events.jsonl"


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy to detect complex vs. default passwords."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob)


def load_and_aggregate_sessions(filepath: str) -> pd.DataFrame:
    """Groups low-level JSONL events into session-level behavioral profiles."""
    if not os.path.exists(filepath):
        print(f"[-] Source file {filepath} not found.")
        return pd.DataFrame()

    records = []
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    if not records:
        return pd.DataFrame()

    df = pd.json_normalize(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    # Aggregate by source IP to build session features
    sessions = []
    for ip, group in df.groupby("src_ip"):
        timestamps = group["timestamp"].sort_values()
        duration = (timestamps.max() - timestamps.min()).total_seconds()
        
        # Auth metrics
        auth_events = group[group["event_type"] == "auth_attempt"]
        auth_attempts = len(auth_events)
        passwords = auth_events["details.password"].dropna().tolist() if "details.password" in group.columns else []
        avg_pass_entropy = np.mean([calculate_entropy(p) for p in passwords]) if passwords else 0.0

        # Command execution metrics
        cmd_events = group[group["event_type"] == "command_exec"]
        cmd_count = len(cmd_events)
        commands = cmd_events["details.command"].dropna().tolist() if "details.command" in group.columns else []
        avg_cmd_len = np.mean([len(c) for c in commands]) if commands else 0.0
        command_corpus = " ".join(commands)

        # Threat intel metrics
        abuse_score = group["intelligence.abuse_score"].dropna().max() if "intelligence.abuse_score" in group.columns else 0.0

        sessions.append({
            "src_ip": ip,
            "session_duration_sec": max(duration, 1.0),
            "auth_attempts": auth_attempts,
            "avg_pass_entropy": round(avg_pass_entropy, 2),
            "command_count": cmd_count,
            "avg_cmd_len": round(avg_cmd_len, 2),
            "abuse_score": abuse_score if not pd.isna(abuse_score) else 0.0,
            "command_corpus": command_corpus
        })

    return pd.DataFrame(sessions)


def train_isolation_forest(session_df: pd.DataFrame):
    """Detects outlier/anomalous attacker behaviors using Isolation Forest."""
    features = [
        "session_duration_sec",
        "auth_attempts",
        "avg_pass_entropy",
        "command_count",
        "avg_cmd_len",
        "abuse_score"
    ]

    X = session_df[features].fillna(0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Contamination defines expected fraction of abnormal traffic (~10%)
    iso = IsolationForest(contamination=0.1, random_state=42)
    session_df["anomaly_label"] = iso.fit_predict(X_scaled)  # -1 = anomaly, 1 = normal
    session_df["anomaly_score"] = iso.decision_function(X_scaled)

    # Convert to readable flag
    session_df["is_anomalous"] = session_df["anomaly_label"].apply(lambda x: True if x == -1 else False)
    return session_df


def cluster_commands(session_df: pd.DataFrame, n_clusters: int = 3):
    """Clusters command sequences via TF-IDF and K-Means to identify campaigns."""
    corpus = session_df["command_corpus"].tolist()
    # Filter sessions with empty command lists
    valid_corpus = [c for c in corpus if c.strip()]

    if len(valid_corpus) < n_clusters:
        print("[!] Not enough unique command sequences to form clusters yet.")
        session_df["campaign_cluster"] = 0
        return session_df

    vectorizer = TfidfVectorizer(max_features=50, stop_words="english")
    tfidf_matrix = vectorizer.fit_transform(session_df["command_corpus"])

    kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init="auto")
    session_df["campaign_cluster"] = kmeans.fit_predict(tfidf_matrix)
    return session_df


def main():
    print(f"[*] Ingesting and aggregating sessions from {SOURCE_LOG}...")
    session_df = load_and_aggregate_sessions(SOURCE_LOG)

    if session_df.empty:
        print("[-] No valid events found. Generate connections to the honeypot first.")
        return

    print(f"[+] Processed {len(session_df)} unique attacker sessions.")

    # 1. Run Anomaly Detection
    session_df = train_isolation_forest(session_df)
    anomalies = session_df[session_df["is_anomalous"]]
    print(f"[+] Isolation Forest complete: Detected {len(anomalies)} anomalous session(s).")

    # 2. Run Payload Clustering
    session_df = cluster_commands(session_df)

    # 3. Output Summary Table
    cols_to_display = [
        "src_ip",
        "auth_attempts",
        "command_count",
        "session_duration_sec",
        "is_anomalous",
        "campaign_cluster"
    ]
    print("\n=== Attacker Profile Analysis Summary ===")
    print(session_df[cols_to_display].to_string(index=False))

    # Save labeled dataset for analytics
    output_path = "session_ml_analysis.csv"
    session_df.to_csv(output_path, index=False)
    print(f"\n[+] Detailed analysis exported to {output_path}")


if __name__ == "__main__":
    main()