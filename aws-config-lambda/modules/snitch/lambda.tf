resource "aws_lambda_permission" "permission" {
  statement_id = "EvaluateRootAccountLambdaInvokePermission"
  function_name = "${aws_lambda_function.function.arn}"
  action = "lambda:InvokeFunction"
  principal = "config.amazonaws.com"
}

resource "aws_lambda_function" "function" {
  function_name = "snitch-${var.env}-lambda"
  handler = "index.handler"
  role = "${aws_iam_role.role.arn}"
  runtime = "nodejs8.10"
  filename = "${var.zip_path}"
  source_code_hash = "${var.source_code_hash}"
  timeout = 300
}

resource "aws_config_config_rule" "rule" {
  name = "snitch-${var.env}-config-rule"

  source {
    owner = "CUSTOM_LAMBDA"
    source_identifier = "${aws_lambda_function.function.arn}"

    source_detail {
      event_source = "aws.config"
      maximum_execution_frequency = "One_Hour"
      message_type = "ScheduledNotification"
    }

    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }

    source_detail {
      event_source = "aws.config"
      message_type = "OversizedConfigurationItemChangeNotification"
    }
  }

  depends_on = ["aws_lambda_permission.permission"]
}