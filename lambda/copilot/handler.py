"""
CloudTrail Threat Hunting Copilot — main Lambda handler
Pipeline: Natural Language → Athena SQL → Execute → Bedrock Analysis → Response
"""
import boto3
import json
import logging
import os
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── Clients (reused across warm invocations) ──────────────────────────────────
bedrock = boto3.client("bedrock-runtime", region_name=os.environ["AWS_REGION"])
athena  = boto3.client("athena")

# ── Environment variables injected by Terraform ───────────────────────────────
BEDROCK_MODEL_ID      = os.environ["BEDROCK_MODEL_ID"]
ATHENA_DATABASE       = os.environ["ATHENA_DATABASE"]
ATHENA_TABLE          = os.environ["ATHENA_TABLE"]
ATHENA_WORKGROUP      = os.environ["ATHENA_WORKGROUP"]
ATHENA_OUTPUT_BUCKET  = os.environ["ATHENA_OUTPUT_BUCKET"]
ATHENA_RESULTS_PREFIX = os.environ.get("ATHENA_RESULTS_PREFIX", "athena-results/")
QUERY_LIMIT           = int(os.environ.get("QUERY_LIMIT", "500"))

# ── CloudTrail schema injected into every NL→SQL prompt ──────────────────────
CLOUDTRAIL_SCHEMA = f"""
Athena database : {ATHENA_DATABASE}
Athena table    : {ATHENA_TABLE}

Key columns
-----------
eventtime        STRING   ISO-8601 timestamp (e.g. '2024-03-15T10:23:45Z')
eventname        STRING   API action name  (e.g. CreateUser, PutBucketPolicy)
eventsource      STRING   AWS service endpoint (e.g. iam.amazonaws.com)
sourceipaddress  STRING   Caller source IP
useragent        STRING   Caller user-agent string
awsregion        STRING   AWS region of the event
errorcode        STRING   Error code if the call failed (NULL on success)
errormessage     STRING   Error message if the call failed
readonly         BOOLEAN  True if the API call is read-only
recipientaccountid STRING AWS account that received the event
requestparameters  STRING JSON-encoded request parameters
responseelements   STRING JSON-encoded response elements
additionaleventdata STRING Extra context (e.g. MFAUsed for ConsoleLogin)

Nested structs (use dot notation)
----------------------------------
useridentity.type       — Root | IAMUser | AssumedRole | AWSService | ...
useridentity.arn        — Full caller ARN
useridentity.accountid  — Caller AWS account ID
useridentity.username   — IAM username (IAMUser type only)
useridentity.sessioncontext.attributes.mfaauthenticated — 'true'/'false'

Array column
------------
resources — ARRAY<STRUCT<arn:STRING, accountid:STRING, type:STRING>>

Useful Athena functions
------------------------
date_add('day', -N, current_date)  → subtract N days
date_format(ts, '%Y-%m-%dT%H:%i:%SZ') → format as ISO-8601 string
json_extract_scalar(col, '$.key')  → extract a scalar from JSON string
LOWER(col)                         → case-insensitive comparison
cardinality(array_col)             → length of an array
"""


# ─────────────────────────────────────────────────────────────────────────────
def _invoke_bedrock(prompt: str, max_tokens: int = 4096) -> str:
    """Call Amazon Bedrock and return the text response."""
    response = bedrock.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }),
    )
    result = json.loads(response["body"].read())
    return result["content"][0]["text"]


# ─────────────────────────────────────────────────────────────────────────────
def natural_language_to_sql(nl_query: str) -> str:
    """Convert a plain-English security question to a valid Athena SQL query."""
    prompt = f"""You are a cloud security expert and Athena SQL specialist.

Convert the security question below to a valid Athena SQL query against the
CloudTrail table described in the schema.

{CLOUDTRAIL_SCHEMA}

Security question: {nl_query}

Rules (MUST follow):
1. Return ONLY the raw SQL — no markdown fences, no explanations.
2. Use proper Presto/Athena SQL syntax.
3. Always include a time filter using eventtime.
4. Limit results to {QUERY_LIMIT} rows unless the question specifies otherwise.
5. Use json_extract_scalar() for JSON fields (requestparameters, etc.).
6. eventtime is a STRING column. NEVER compare it to a timestamp directly.
   ALWAYS use this exact pattern for date filtering:
   eventtime >= date_format(date_add('day', -N, current_date), '%Y-%m-%dT%H:%i:%SZ')
   For example, last 7 days: eventtime >= date_format(date_add('day', -7, current_date), '%Y-%m-%dT%H:%i:%SZ')
7. Use LOWER() for case-insensitive string matching.
8. Use double-quoted identifiers: "{ATHENA_DATABASE}"."{ATHENA_TABLE}"

Return ONLY the SQL statement — nothing else."""

    raw = _invoke_bedrock(prompt, max_tokens=2000).strip()

    # Strip accidental markdown fences
    if raw.startswith("```"):
        lines = raw.split("\n")
        raw = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

    return raw.strip()


# ─────────────────────────────────────────────────────────────────────────────
def _run_athena_query(sql: str) -> list[dict]:
    """Execute an Athena SQL query and return all result rows as dicts."""
    response = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": ATHENA_DATABASE},
        ResultConfiguration={
            "OutputLocation": f"s3://{ATHENA_OUTPUT_BUCKET}/{ATHENA_RESULTS_PREFIX}"
        },
        WorkGroup=ATHENA_WORKGROUP,
    )
    exec_id = response["QueryExecutionId"]

    # Poll until the query finishes (max 5 min — matches Lambda timeout)
    deadline = time.time() + 280
    while time.time() < deadline:
        status = athena.get_query_execution(QueryExecutionId=exec_id)
        state  = status["QueryExecution"]["Status"]["State"]

        if state == "SUCCEEDED":
            break
        if state in ("FAILED", "CANCELLED"):
            reason = status["QueryExecution"]["Status"].get("StateChangeReason", "unknown")
            raise RuntimeError(f"Athena query {state}: {reason}")

        time.sleep(2)
    else:
        raise TimeoutError("Athena query did not complete within the allowed window")

    # Paginate results and convert to list-of-dicts
    rows: list[dict] = []
    columns: list[str] | None = None

    paginator = athena.get_paginator("get_query_results")
    for page in paginator.paginate(QueryExecutionId=exec_id):
        page_rows = page["ResultSet"]["Rows"]

        if columns is None:
            columns = [c["VarCharValue"] for c in page_rows[0]["Data"]]
            page_rows = page_rows[1:]  # skip header row

        for row in page_rows:
            rows.append(
                {
                    columns[i]: cell.get("VarCharValue", "")
                    for i, cell in enumerate(row["Data"])
                    if i < len(columns)
                }
            )

    return rows


# ─────────────────────────────────────────────────────────────────────────────
def analyze_results(nl_query: str, sql: str, rows: list[dict]) -> dict:
    """Send query results to Bedrock for threat analysis + MITRE ATT&CK mapping."""
    prompt = f"""You are a senior cloud security threat hunter analyzing AWS CloudTrail data.

Security question  : {nl_query}
SQL query executed :
{sql}

Query results ({len(rows)} rows — showing first 50):
{json.dumps(rows[:50], indent=2, default=str)}

Analyze these results as a threat hunter and return a single JSON object with
exactly the following structure (no markdown, no extra text):

{{
  "summary": "<2-3 sentence executive summary>",
  "total_events_analyzed": {len(rows)},
  "threat_detected": <true|false>,
  "confidence_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
  "risk_score": <0-100>,
  "key_findings": ["<finding 1>", "..."],
  "suspicious_patterns": ["<pattern 1>", "..."],
  "affected_resources": ["<resource ARN or description>", "..."],
  "affected_accounts": ["<account ID>", "..."],
  "mitre_attack_mapping": [
    {{
      "technique_id": "<T####.###>",
      "technique_name": "<name>",
      "tactic": "<tactic>",
      "relevance": "<High|Medium|Low>"
    }}
  ],
  "recommended_actions": ["<action 1>", "..."],
  "follow_up_queries": [
    "<plain-English follow-up question 1>",
    "<plain-English follow-up question 2>",
    "<plain-English follow-up question 3>"
  ],
  "false_positive_indicators": ["<indicator 1>", "..."]
}}

Return ONLY the JSON object."""

    raw = _invoke_bedrock(prompt, max_tokens=1024)

    # Strip markdown if present
    if "```json" in raw:
        start = raw.find("```json") + 7
        end   = raw.find("```", start)
        raw   = raw[start:end].strip()
    elif raw.startswith("```"):
        lines = raw.split("\n")
        raw   = "\n".join(lines[1:-1]).strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("Bedrock response was not valid JSON — returning raw text")
        return {
            "summary": raw,
            "total_events_analyzed": len(rows),
            "threat_detected": False,
            "confidence_level": "LOW",
            "risk_score": 0,
            "key_findings": [],
            "suspicious_patterns": [],
            "affected_resources": [],
            "affected_accounts": [],
            "mitre_attack_mapping": [],
            "recommended_actions": [],
            "follow_up_queries": [],
            "false_positive_indicators": [],
        }


# ─────────────────────────────────────────────────────────────────────────────
def copilot(question: str) -> dict:
    """
    Three-stage copilot pipeline:
      1. NL → SQL  (Bedrock)
      2. Execute   (Athena)
      3. Analyze   (Bedrock)
    """
    logger.info("Stage 1: NL→SQL | question=%s", question)
    sql = natural_language_to_sql(question)
    logger.info("Stage 1 done | sql=%s", sql)

    logger.info("Stage 2: Athena execution")
    rows = _run_athena_query(sql)
    logger.info("Stage 2 done | rows=%d", len(rows))

    logger.info("Stage 3: Bedrock analysis")
    analysis = analyze_results(question, sql, rows)
    logger.info(
        "Stage 3 done | threat=%s confidence=%s risk=%s",
        analysis.get("threat_detected"),
        analysis.get("confidence_level"),
        analysis.get("risk_score"),
    )

    return {
        "question":      question,
        "sql_generated": sql,
        "rows_returned": len(rows),
        "analysis":      analysis,
        "sample_rows":   rows[:10],  # first 10 rows for quick reference
    }


# ─────────────────────────────────────────────────────────────────────────────
def lambda_handler(event, context):
    """Lambda entry-point — accepts API Gateway proxy events or raw JSON."""
    logger.info("Event received: %s", json.dumps(event))

    try:
        # Support both API Gateway proxy and direct Lambda invocations
        if "body" in event:
            body = json.loads(event["body"]) if isinstance(event["body"], str) else event["body"]
        else:
            body = event

        question = (body.get("question") or "").strip()
        if not question:
            return _response(400, {"error": "Field 'question' is required"})

        result = copilot(question)

        # Structured audit log entry (CloudWatch Logs Insights queryable)
        logger.info(
            json.dumps({
                "event_type":       "copilot_query",
                "question":         question,
                "sql":              result["sql_generated"],
                "rows_returned":    result["rows_returned"],
                "threat_detected":  result["analysis"].get("threat_detected"),
                "confidence":       result["analysis"].get("confidence_level"),
                "risk_score":       result["analysis"].get("risk_score"),
            })
        )

        return _response(200, result)

    except Exception as exc:
        logger.exception("Unhandled error: %s", exc)
        return _response(500, {"error": str(exc)})


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {
            "Content-Type":                "application/json",
            "Access-Control-Allow-Origin": "*",
        },
        "body": json.dumps(body, default=str),
    }
