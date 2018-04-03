variable "vpc_id" {}

resource "aws_flow_log" "test_flow_log" {
  log_group_name = "My Log Group"
  iam_role_arn   = "${aws_iam_role.test_role.arn}"
  vpc_id         = "${var.vpc_id}"
  traffic_type   = "ALL"
}

resource "aws_iam_role" "test_role" {
  name = "test_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}