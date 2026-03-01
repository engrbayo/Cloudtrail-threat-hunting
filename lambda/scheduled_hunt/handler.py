"""
Scheduled Threat Hunt Lambda
Runs a set of predefined threat-hunting queries via the Copilot Lambda,
publishes custom CloudWatch metrics, and sends SNS alerts on HIGH/CRITICAL hits.
"""
import boto3
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

lambda_client = boto3.client("lambda")
cloudwatch    = boto3.client("cloudwatch")
sns           = boto3.client("sns")

COPILOT_FUNCTION_NAME = os.environ["COPILOT_FUNCTION_NAME"]
SNS_TOPIC_ARN         = os.environ.get("SNS_TOPIC_ARN", "")
ALERT_THRESHOLD       = os.environ.get("ALERT_THRESHOLD", "HIGH")   # LOW|MEDIUM|HIGH|CRITICAL

# Ordered threat confidence levels (used for threshold comparison)
CONFIDENCE_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Predefined hunt queries — each maps to a plain-English question the
# copilot converts to SQL automatically.
HUNT_QUERIES: list[dict] = [
    {
        "name":  "Root Account Usage",
        "query": "Show all root account logins and API calls in the last 24 hours",
    },
    {
        "name":  "IAM Privilege Escalation",
        "query": "Find any IAM role creations with admin policies attached today",
    },
    {
        "name":  "Geographic Anomaly",
        "query": "Detect unusual high-volume API activity from non-private IP addresses in the last 24 hours",
    },
    {
        "name":  "MFA Bypass",
        "query": "Find any console logins where MFA was not used in the last 24 hours",
    },
    {
        "name":  "Cross-Account Lateral Movement",
        "query": "Identify principals that assumed roles in more than 2 accounts today",
    },
    {
        "name":  "CloudTrail Tampering",
        "query": "Find any attempts to stop, delete, or modify CloudTrail logging today",
    },
    {
        "name":  "Security Group Exposure",
        "query": "Show all security group changes that opened ingress to 0.0.0.0/0 today",
    },
    {
        "name":  "IAM Access Key Creation",
        "query": "Find any new IAM access keys created in the last 24 hours",
    },
    {
        "name":  "S3 Bucket Policy Changes",
        "query": "Show all S3 bucket policy modifications or public access changes today",
    },
    {
        "name":  "Secrets Manager Access",
        "query": "Find any unusual Secrets Manager GetSecretValue calls from new principals today",
    },
]


def _invoke_copilot(query: str) -> dict | None:
    """Invoke the copilot Lambda synchronously and return parsed result."""
    try:
        response = lambda_client.invoke(
            FunctionName=COPILOT_FUNCTION_NAME,
            InvocationType="RequestResponse",
            Payload=json.dumps({"question": query}),
        )
        payload = json.loads(response["Payload"].read())
        if payload.get("statusCode") != 200:
            logger.warning("Copilot returned %s for query: %s", payload.get("statusCode"), query)
            return None
        return json.loads(payload.get("body", "{}"))
    except Exception as exc:
        logger.error("Copilot invocation failed for query '%s': %s", query, exc)
        return None


def _put_metrics(hunt_name: str, analysis: dict):
    """Publish per-hunt metrics to CloudWatch under ThreatHuntingCopilot namespace."""
    threat_detected = 1 if analysis.get("threat_detected") else 0
    risk_score      = int(analysis.get("risk_score", 0))
    confidence      = analysis.get("confidence_level", "LOW")

    cloudwatch.put_metric_data(
        Namespace="ThreatHuntingCopilot",
        MetricData=[
            {
                "MetricName": "HuntExecuted",
                "Dimensions": [{"Name": "HuntName", "Value": hunt_name}],
                "Value": 1,
                "Unit":  "Count",
            },
            {
                "MetricName": "ThreatDetected",
                "Dimensions": [{"Name": "HuntName", "Value": hunt_name}],
                "Value": threat_detected,
                "Unit":  "Count",
            },
            {
                "MetricName": "RiskScore",
                "Dimensions": [{"Name": "HuntName", "Value": hunt_name}],
                "Value": risk_score,
                "Unit":  "None",
            },
            {
                "MetricName": f"Confidence_{confidence}",
                "Dimensions": [{"Name": "HuntName", "Value": hunt_name}],
                "Value": 1,
                "Unit":  "Count",
            },
        ],
    )


def _should_alert(confidence: str) -> bool:
    return CONFIDENCE_RANK.get(confidence, 0) >= CONFIDENCE_RANK.get(ALERT_THRESHOLD, 2)


def _send_sns_alert(threats: list[dict]):
    """Publish a formatted threat summary to the SNS topic."""
    if not SNS_TOPIC_ARN:
        logger.info("SNS_TOPIC_ARN not set — skipping alert")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        f"THREAT HUNT ALERT — {timestamp}",
        f"Found {len(threats)} threat(s) at or above {ALERT_THRESHOLD} confidence",
        "",
    ]

    for t in threats:
        lines += [
            f"[{t['confidence']}] {t['name']}  |  Risk Score: {t['risk_score']}",
            f"  Summary : {t['summary']}",
            f"  MITRE   : {', '.join(m['technique_id'] for m in t.get('mitre_mapping', []))}",
            f"  Actions : {'; '.join(t.get('recommended_actions', [])[:3])}",
            "",
        ]

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=f"[THREAT HUNT] {len(threats)} HIGH/CRITICAL threat(s) detected",
        Message="\n".join(lines),
    )
    logger.info("SNS alert published for %d threats", len(threats))


def lambda_handler(event, context):
    """EventBridge Scheduler entry-point."""
    logger.info("Starting scheduled threat hunt — %d queries", len(HUNT_QUERIES))

    summary    = {"executed": 0, "threats_found": 0, "errors": 0, "details": []}
    alert_list = []

    for hunt in HUNT_QUERIES:
        name  = hunt["name"]
        query = hunt["query"]
        logger.info("Running hunt: %s", name)

        result = _invoke_copilot(query)
        if result is None:
            summary["errors"] += 1
            continue

        summary["executed"] += 1
        analysis   = result.get("analysis", {})
        confidence = analysis.get("confidence_level", "LOW")
        risk_score = analysis.get("risk_score", 0)
        detected   = analysis.get("threat_detected", False)

        _put_metrics(name, analysis)

        if detected:
            summary["threats_found"] += 1

        entry = {
            "name":       name,
            "query":      query,
            "threat":     detected,
            "confidence": confidence,
            "risk_score": risk_score,
            "summary":    analysis.get("summary", ""),
        }
        summary["details"].append(entry)

        if detected and _should_alert(confidence):
            alert_list.append({
                **entry,
                "mitre_mapping":       analysis.get("mitre_attack_mapping", []),
                "recommended_actions": analysis.get("recommended_actions", []),
            })

    if alert_list:
        _send_sns_alert(alert_list)

    # Aggregate metric: total threats this run
    cloudwatch.put_metric_data(
        Namespace="ThreatHuntingCopilot",
        MetricData=[
            {
                "MetricName": "TotalThreatsPerRun",
                "Value": summary["threats_found"],
                "Unit":  "Count",
            }
        ],
    )

    logger.info("Hunt complete: %s", json.dumps(summary))
    return summary
