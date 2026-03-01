"""
CloudTrail Threat Hunting Copilot — Streamlit Chat UI
Sends natural-language questions to the API Gateway → Lambda → Bedrock pipeline.
"""
import json
import os
import time

import requests
import streamlit as st

# ── Config ────────────────────────────────────────────────────────────────────
API_URL = os.environ.get("API_GATEWAY_URL", "").rstrip("/")
QUERY_ENDPOINT = f"{API_URL}/query"
REQUEST_TIMEOUT = 300  # seconds — matches Lambda timeout

CONFIDENCE_COLORS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}

EXAMPLE_QUERIES = [
    "Show all root account logins in the last 30 days",
    "Find any IAM role creations with admin policies attached this week",
    "Detect unusual API activity from non-US IP addresses yesterday",
    "Find any console logins where MFA was not used in the last 90 days",
    "Identify EC2 instances that assumed roles in more than 3 accounts today",
    "Show all CloudTrail logging changes in the last 7 days",
    "Find new IAM access keys created in the last 24 hours",
    "Show S3 bucket policy changes from the past week",
]

# ── Page setup ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="CloudTrail Threat Hunting Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🛡️ CloudTrail Threat Hunting Copilot")
st.markdown(
    "_Ask questions in plain English — the copilot converts them to "
    "Athena SQL, executes against your CloudTrail logs, and provides "
    "MITRE ATT&CK-mapped threat analysis._"
)

# ── Sidebar — example queries ─────────────────────────────────────────────────
with st.sidebar:
    st.header("Example Queries")
    st.markdown("Click any query to load it:")
    for q in EXAMPLE_QUERIES:
        if st.button(q, key=q):
            st.session_state["prefill"] = q

    st.divider()
    st.caption("API endpoint: " + (QUERY_ENDPOINT if API_URL else "⚠️ Not configured"))

# ── Chat history ──────────────────────────────────────────────────────────────
if "messages" not in st.session_state:
    st.session_state["messages"] = []

for msg in st.session_state["messages"]:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# ── Input ─────────────────────────────────────────────────────────────────────
prefill = st.session_state.pop("prefill", None)
question = st.chat_input(
    "Ask a threat hunting question…",
    key="chat_input",
) or prefill

if question:
    # Display user message
    with st.chat_message("user"):
        st.markdown(question)
    st.session_state["messages"].append({"role": "user", "content": question})

    # Call the API
    with st.chat_message("assistant"):
        with st.spinner("🔍 Querying CloudTrail via Athena + Bedrock…"):
            start = time.time()
            try:
                resp = requests.post(
                    QUERY_ENDPOINT,
                    json={"question": question},
                    timeout=REQUEST_TIMEOUT,
                )
                elapsed = time.time() - start

                if resp.status_code != 200:
                    st.error(f"API error {resp.status_code}: {resp.text}")
                    st.stop()

                data     = resp.json()
                analysis = data.get("analysis", {})

                # ── Confidence + risk banner ──────────────────────────────
                confidence = analysis.get("confidence_level", "LOW")
                risk_score = analysis.get("risk_score", 0)
                threat     = analysis.get("threat_detected", False)
                emoji      = CONFIDENCE_COLORS.get(confidence, "⚪")

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Threat Detected", "YES ⚠️" if threat else "No ✅")
                col2.metric("Confidence", f"{emoji} {confidence}")
                col3.metric("Risk Score", f"{risk_score}/100")
                col4.metric("Rows Analyzed", data.get("rows_returned", 0))

                # ── Executive summary ─────────────────────────────────────
                st.subheader("📋 Summary")
                st.info(analysis.get("summary", "No summary available."))

                # ── Generated SQL ─────────────────────────────────────────
                with st.expander("🔧 Generated Athena SQL"):
                    st.code(data.get("sql_generated", ""), language="sql")

                # ── Key findings ──────────────────────────────────────────
                if analysis.get("key_findings"):
                    st.subheader("🔍 Key Findings")
                    for f in analysis["key_findings"]:
                        st.markdown(f"- {f}")

                # ── Suspicious patterns ───────────────────────────────────
                if analysis.get("suspicious_patterns"):
                    st.subheader("⚠️ Suspicious Patterns")
                    for p in analysis["suspicious_patterns"]:
                        st.markdown(f"- {p}")

                # ── MITRE ATT&CK mapping ──────────────────────────────────
                if analysis.get("mitre_attack_mapping"):
                    st.subheader("🗺️ MITRE ATT&CK Mapping")
                    for m in analysis["mitre_attack_mapping"]:
                        st.markdown(
                            f"- **{m.get('technique_id')}** — {m.get('technique_name')} "
                            f"(_Tactic: {m.get('tactic')}_, Relevance: {m.get('relevance')})"
                        )

                # ── Recommended actions ───────────────────────────────────
                if analysis.get("recommended_actions"):
                    st.subheader("✅ Recommended Actions")
                    for i, a in enumerate(analysis["recommended_actions"], 1):
                        st.markdown(f"{i}. {a}")

                # ── Affected resources ────────────────────────────────────
                cols = st.columns(2)
                if analysis.get("affected_resources"):
                    with cols[0]:
                        st.subheader("🖥️ Affected Resources")
                        for r in analysis["affected_resources"]:
                            st.markdown(f"- `{r}`")
                if analysis.get("affected_accounts"):
                    with cols[1]:
                        st.subheader("☁️ Affected Accounts")
                        for a in analysis["affected_accounts"]:
                            st.markdown(f"- `{a}`")

                # ── Sample results ────────────────────────────────────────
                if data.get("sample_rows"):
                    with st.expander(f"📊 Sample Results (first {len(data['sample_rows'])} rows)"):
                        st.json(data["sample_rows"])

                # ── Follow-up queries ─────────────────────────────────────
                if analysis.get("follow_up_queries"):
                    st.subheader("➡️ Follow-up Investigations")
                    for fq in analysis["follow_up_queries"]:
                        if st.button(f"🔎 {fq}", key=fq):
                            st.session_state["prefill"] = fq
                            st.rerun()

                st.caption(f"Analysis completed in {elapsed:.1f}s")

                # Store assistant reply summary in chat history
                reply = (
                    f"**{emoji} {confidence} confidence** | Risk score: {risk_score}/100\n\n"
                    + analysis.get("summary", "")
                )
                st.session_state["messages"].append({"role": "assistant", "content": reply})

            except requests.Timeout:
                st.error("⏱️ Request timed out. The query may be too broad — try narrowing the time range.")
            except Exception as exc:
                st.error(f"❌ Unexpected error: {exc}")
