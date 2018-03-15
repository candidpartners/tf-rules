
data "archive_file" "lambda_code" {
  source_dir = "${path.module}/../src"
  type = "zip"
  output_path = "${path.module}/function.zip"
}

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
  runtime = "nodejs6.10"
  filename = "${data.archive_file.lambda_code.output_path}"
  source_code_hash = "${data.archive_file.lambda_code.output_base64sha256}"
  timeout = 10
}

resource "aws_config_config_rule" "rule" {
  name = "snitch-${var.env}-config-rule"

  source {
    owner = "CUSTOM_LAMBDA"
    source_identifier = "${aws_lambda_function.function.arn}"
    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
  }
  depends_on = ["aws_lambda_permission.permission"]
}