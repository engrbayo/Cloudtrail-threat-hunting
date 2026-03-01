# ─────────────────────────────────────────────────────────────────────────────
# Athena Workgroup — scoped, cost-controlled query environment
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_athena_workgroup" "copilot" {
  name        = "${local.name_prefix}-workgroup"
  description = "Athena workgroup for the CloudTrail Threat Hunting Copilot"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    bytes_scanned_cutoff_per_query     = 10737418240 # 10 GB hard limit per query

    result_configuration {
      output_location = "s3://${aws_s3_bucket.audit.id}/${var.athena_results_prefix}"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }

  tags = { Name = "${local.name_prefix}-workgroup" }
}

# ─────────────────────────────────────────────────────────────────────────────
# Athena Named Queries — pre-built threat hunt templates
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_athena_named_query" "root_account_usage" {
  name        = "Hunt-RootAccountUsage"
  description = "Find all root account API calls in the last 30 days"
  database    = aws_glue_catalog_database.cloudtrail.name
  workgroup   = aws_athena_workgroup.copilot.name

  query = <<-SQL
    SELECT
      eventtime,
      eventname,
      eventsource,
      sourceipaddress,
      useragent,
      awsregion,
      errorcode
    FROM "${local.glue_database_name}"."${local.glue_table_name}"
    WHERE useridentity.type = 'Root'
      AND eventtime >= date_format(date_add('day', -30, current_date), '%Y-%m-%dT%H:%i:%SZ')
    ORDER BY eventtime DESC
    LIMIT 500;
  SQL
}

resource "aws_athena_named_query" "iam_admin_role_creation" {
  name        = "Hunt-IAMAdminRoleCreation"
  description = "Find IAM roles created with admin-level policies attached this week"
  database    = aws_glue_catalog_database.cloudtrail.name
  workgroup   = aws_athena_workgroup.copilot.name

  query = <<-SQL
    SELECT
      eventtime,
      useridentity.arn        AS caller_arn,
      useridentity.type       AS identity_type,
      eventname,
      sourceipaddress,
      json_extract_scalar(requestparameters, '$.roleName')  AS role_name,
      json_extract_scalar(requestparameters, '$.policyArn') AS policy_arn,
      awsregion
    FROM "${local.glue_database_name}"."${local.glue_table_name}"
    WHERE eventsource = 'iam.amazonaws.com'
      AND eventname IN ('CreateRole', 'AttachRolePolicy', 'PutRolePolicy')
      AND (
        json_extract_scalar(requestparameters, '$.policyArn')
          = 'arn:aws:iam::aws:policy/AdministratorAccess'
        OR LOWER(requestparameters) LIKE '%"effect":"allow"%"action":"*"%"resource":"*"%'
      )
      AND eventtime >= date_format(date_add('day', -7, current_date), '%Y-%m-%dT%H:%i:%SZ')
    ORDER BY eventtime DESC
    LIMIT 500;
  SQL
}

resource "aws_athena_named_query" "geo_anomaly" {
  name        = "Hunt-GeoAnomaly"
  description = "High-volume API activity from non-RFC1918, non-AWS IP addresses"
  database    = aws_glue_catalog_database.cloudtrail.name
  workgroup   = aws_athena_workgroup.copilot.name

  query = <<-SQL
    SELECT
      sourceipaddress,
      COUNT(*)                        AS event_count,
      array_agg(DISTINCT eventname)  AS actions,
      array_agg(DISTINCT eventsource) AS services,
      MIN(eventtime)                  AS first_seen,
      MAX(eventtime)                  AS last_seen
    FROM "${local.glue_database_name}"."${local.glue_table_name}"
    WHERE errorcode IS NULL
      AND sourceipaddress NOT LIKE '%.amazonaws.com'
      AND sourceipaddress NOT LIKE '10.%'
      AND sourceipaddress NOT LIKE '172.1%'
      AND sourceipaddress NOT LIKE '172.2%'
      AND sourceipaddress NOT LIKE '172.3%'
      AND sourceipaddress NOT LIKE '192.168.%'
      AND eventtime >= date_format(date_add('day', -1, current_date), '%Y-%m-%dT%H:%i:%SZ')
    GROUP BY sourceipaddress
    HAVING COUNT(*) > 10
    ORDER BY event_count DESC
    LIMIT 500;
  SQL
}

resource "aws_athena_named_query" "mfa_bypass" {
  name        = "Hunt-MFABypass"
  description = "Console logins where MFA was NOT used in the last 90 days"
  database    = aws_glue_catalog_database.cloudtrail.name
  workgroup   = aws_athena_workgroup.copilot.name

  query = <<-SQL
    SELECT
      eventtime,
      useridentity.username  AS username,
      useridentity.type      AS identity_type,
      sourceipaddress,
      useragent,
      json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa_used,
      awsregion
    FROM "${local.glue_database_name}"."${local.glue_table_name}"
    WHERE eventname = 'ConsoleLogin'
      AND json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No'
      AND errorcode IS NULL
      AND eventtime >= date_format(date_add('day', -90, current_date), '%Y-%m-%dT%H:%i:%SZ')
    ORDER BY eventtime DESC
    LIMIT 500;
  SQL
}

resource "aws_athena_named_query" "lateral_movement" {
  name        = "Hunt-LateralMovement"
  description = "EC2 instances that assumed roles across more than 2 accounts today"
  database    = aws_glue_catalog_database.cloudtrail.name
  workgroup   = aws_athena_workgroup.copilot.name

  query = <<-SQL
    SELECT
      useridentity.arn             AS principal_arn,
      COUNT(DISTINCT recipientaccountid) AS accounts_accessed,
      array_agg(DISTINCT recipientaccountid) AS account_list,
      COUNT(*)                     AS total_sts_calls,
      MIN(eventtime)               AS first_seen,
      MAX(eventtime)               AS last_seen
    FROM "${local.glue_database_name}"."${local.glue_table_name}"
    WHERE eventsource = 'sts.amazonaws.com'
      AND eventname   = 'AssumeRole'
      AND useridentity.type = 'AssumedRole'
      AND LOWER(useridentity.arn) LIKE '%ec2%'
      AND eventtime >= date_format(current_date, '%Y-%m-%dT%H:%i:%SZ')
    GROUP BY useridentity.arn
    HAVING COUNT(DISTINCT recipientaccountid) > 2
    ORDER BY accounts_accessed DESC
    LIMIT 500;
  SQL
}

resource "aws_athena_named_query" "cloudtrail_tampering" {
  name        = "Hunt-CloudTrailTampering"
  description = "Attempts to stop, delete, or modify CloudTrail logging"
  database    = aws_glue_catalog_database.cloudtrail.name
  workgroup   = aws_athena_workgroup.copilot.name

  query = <<-SQL
    SELECT
      eventtime,
      useridentity.arn AS caller_arn,
      eventname,
      sourceipaddress,
      useragent,
      json_extract_scalar(requestparameters, '$.name') AS trail_name,
      awsregion
    FROM "${local.glue_database_name}"."${local.glue_table_name}"
    WHERE eventsource = 'cloudtrail.amazonaws.com'
      AND eventname IN (
        'StopLogging', 'DeleteTrail', 'UpdateTrail',
        'PutEventSelectors', 'DeleteEventDataStore'
      )
      AND eventtime >= date_format(date_add('day', -7, current_date), '%Y-%m-%dT%H:%i:%SZ')
    ORDER BY eventtime DESC
    LIMIT 500;
  SQL
}

resource "aws_athena_named_query" "s3_data_exfil" {
  name        = "Hunt-S3DataExfiltration"
  description = "High-volume S3 GetObject by external principals this month"
  database    = aws_glue_catalog_database.cloudtrail.name
  workgroup   = aws_athena_workgroup.copilot.name

  query = <<-SQL
    SELECT
      useridentity.arn AS caller_arn,
      sourceipaddress,
      json_extract_scalar(requestparameters, '$.bucketName') AS bucket_name,
      COUNT(*)         AS get_object_count,
      MIN(eventtime)   AS first_access,
      MAX(eventtime)   AS last_access
    FROM "${local.glue_database_name}"."${local.glue_table_name}"
    WHERE eventsource = 's3.amazonaws.com'
      AND eventname   = 'GetObject'
      AND errorcode IS NULL
      AND eventtime >= date_format(date_add('day', -30, current_date), '%Y-%m-%dT%H:%i:%SZ')
    GROUP BY
      useridentity.arn,
      sourceipaddress,
      json_extract_scalar(requestparameters, '$.bucketName')
    HAVING COUNT(*) > 100
    ORDER BY get_object_count DESC
    LIMIT 500;
  SQL
}

resource "aws_athena_named_query" "open_security_groups" {
  name        = "Hunt-OpenSecurityGroupChanges"
  description = "Security group ingress rules opened to 0.0.0.0/0"
  database    = aws_glue_catalog_database.cloudtrail.name
  workgroup   = aws_athena_workgroup.copilot.name

  query = <<-SQL
    SELECT
      eventtime,
      useridentity.arn AS caller_arn,
      eventname,
      sourceipaddress,
      requestparameters,
      awsregion
    FROM "${local.glue_database_name}"."${local.glue_table_name}"
    WHERE eventsource = 'ec2.amazonaws.com'
      AND eventname IN ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress')
      AND requestparameters LIKE '%0.0.0.0/0%'
      AND errorcode IS NULL
      AND eventtime >= date_format(date_add('day', -7, current_date), '%Y-%m-%dT%H:%i:%SZ')
    ORDER BY eventtime DESC
    LIMIT 500;
  SQL
}
