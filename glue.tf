# ─────────────────────────────────────────────────────────────────────────────
# Glue — Database + Table for CloudTrail S3 logs
# Used when enable_cloudtrail_lake = false (S3 + Glue + Athena path)
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_glue_catalog_database" "cloudtrail" {
  name        = local.glue_database_name
  description = "CloudTrail event logs for ${local.name_prefix} threat hunting"
}

# CloudTrail Parquet table schema matching the AWS-documented column set
resource "aws_glue_catalog_table" "cloudtrail_events" {
  name          = local.glue_table_name
  database_name = aws_glue_catalog_database.cloudtrail.name
  description   = "CloudTrail event records stored as JSON in S3"

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"                     = "cloudtrail"
    "EXTERNAL"                           = "TRUE"
    "projection.enabled"                 = "true"
    "projection.timestamp.type"          = "date"
    "projection.timestamp.format"        = "yyyy/MM/dd"
    "projection.timestamp.range"         = "2020/01/01,NOW"
    "projection.timestamp.interval"      = "1"
    "projection.timestamp.interval.unit" = "DAYS"
    "storage.location.template"          = "s3://${aws_s3_bucket.cloudtrail_logs.id}/${var.cloudtrail_log_prefix}AWSLogs/${local.account_id}/CloudTrail/${local.region}/$${timestamp}/"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.cloudtrail_logs.id}/${var.cloudtrail_log_prefix}AWSLogs/${local.account_id}/CloudTrail/${local.region}/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
      parameters            = { "serialization.format" = "1" }
    }

    columns {
      name    = "eventversion"
      type    = "string"
      comment = "CloudTrail event schema version"
    }
    columns {
      name    = "useridentity"
      type    = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
      comment = "User/role that made the API call"
    }
    columns {
      name    = "eventtime"
      type    = "string"
      comment = "ISO-8601 timestamp of the event"
    }
    columns {
      name    = "eventsource"
      type    = "string"
      comment = "AWS service endpoint (e.g. iam.amazonaws.com)"
    }
    columns {
      name    = "eventname"
      type    = "string"
      comment = "API action name (e.g. CreateUser)"
    }
    columns {
      name    = "awsregion"
      type    = "string"
      comment = "AWS region where the event occurred"
    }
    columns {
      name    = "sourceipaddress"
      type    = "string"
      comment = "Source IP address of the API request"
    }
    columns {
      name    = "useragent"
      type    = "string"
      comment = "User agent string from the request"
    }
    columns {
      name    = "errorcode"
      type    = "string"
      comment = "Error code if the API call failed"
    }
    columns {
      name    = "errormessage"
      type    = "string"
      comment = "Error message if the API call failed"
    }
    columns {
      name    = "requestparameters"
      type    = "string"
      comment = "JSON-encoded request parameters"
    }
    columns {
      name    = "responseelements"
      type    = "string"
      comment = "JSON-encoded response elements"
    }
    columns {
      name    = "additionaleventdata"
      type    = "string"
      comment = "Additional data not part of the API request/response"
    }
    columns {
      name    = "requestid"
      type    = "string"
      comment = "Unique ID assigned to the request"
    }
    columns {
      name    = "eventid"
      type    = "string"
      comment = "GUID uniquely identifying the event"
    }
    columns {
      name    = "resources"
      type    = "array<struct<arn:string,accountid:string,type:string>>"
      comment = "List of AWS resources accessed by the event"
    }
    columns {
      name    = "eventtype"
      type    = "string"
      comment = "Type of event (AwsApiCall, AwsConsoleSignIn, etc.)"
    }
    columns {
      name    = "apiversion"
      type    = "string"
      comment = "API version of the identified event"
    }
    columns {
      name    = "readonly"
      type    = "boolean"
      comment = "Whether the event is a read-only operation"
    }
    columns {
      name    = "recipientaccountid"
      type    = "string"
      comment = "Account ID that received the event"
    }
    columns {
      name    = "serviceeventdetails"
      type    = "string"
      comment = "Additional service-specific event details"
    }
    columns {
      name    = "sharedeventid"
      type    = "string"
      comment = "GUID identifying the same event across accounts"
    }
    columns {
      name    = "vpcendpointid"
      type    = "string"
      comment = "VPC endpoint ID if the event was via VPC endpoint"
    }
  }

  partition_keys {
    name = "timestamp"
    type = "string"
  }
}

# ─────────────────────────────────────────────────────────────────────────────
# Glue Crawler — auto-discovers new partitions from S3 daily
# Keeps the table partition metadata fresh for accurate Athena queries
# ─────────────────────────────────────────────────────────────────────────────
resource "aws_glue_crawler" "cloudtrail" {
  name          = "${local.name_prefix}-cloudtrail-crawler"
  description   = "Daily crawl of CloudTrail S3 logs to update partitions"
  role          = aws_iam_role.glue_crawler.arn
  database_name = aws_glue_catalog_database.cloudtrail.name
  schedule      = "cron(0 3 * * ? *)" # 03:00 UTC — after CloudTrail delivers nightly logs

  s3_target {
    path = "s3://${aws_s3_bucket.cloudtrail_logs.id}/${var.cloudtrail_log_prefix}AWSLogs/${local.account_id}/CloudTrail/"
  }

  schema_change_policy {
    update_behavior = "UPDATE_IN_DATABASE"
    delete_behavior = "LOG"
  }

  configuration = jsonencode({
    Version = 1.0
    CrawlerOutput = {
      Partitions = { AddOrUpdateBehavior = "InheritFromTable" }
    }
  })
}
