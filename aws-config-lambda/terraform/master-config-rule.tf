data "aws_iam_policy_document" "assume" {
  statement {
    effect = "Allow"
    principals {
      identifiers = ["lambda.amazonaws.com"]
      type = "Service"
    }
    actions = ["sts:AssumeRole"]
  }
}
resource "aws_iam_role" "role" {
  name = "tf-rules-${var.env}-MasterConfigRole"
  assume_role_policy = "${data.aws_iam_policy_document.assume.json}"
}

resource "aws_iam_role_policy_attachment" "AmazonEC2ReadOnlyAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
  role = "${aws_iam_role.role.id}"
}

resource "aws_iam_role_policy_attachment" "AWSCloudTrailReadOnlyAccess" {
  policy_arn = "arn:aws:iam::aws:policy/AWSCloudTrailReadOnlyAccess"
  role = "${aws_iam_role.role.id}"
}

resource "aws_iam_role_policy_attachment" "IAMReadOnlyAccess" {
  policy_arn = "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
  role = "${aws_iam_role.role.id}"
}

resource "aws_iam_role_policy_attachment" "AWSConfigRulesExecutionRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole"
  role = "${aws_iam_role.role.id}"
}

resource "aws_iam_role_policy_attachment" "AWSLambdaBasicExecutionRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role = "${aws_iam_role.role.id}"
}

data "aws_iam_policy_document" "master_config" {
  statement {
    effect = "Allow"
    resources = ["*"]
    actions = [
      "kms:GetKeyRotationStatus",
      "kms:ListKeys",
    ]
  }

  statement {
    effect = "Allow"
    resources = ["*"]
    actions = [
      "s3:GetBucketAcl",
      "s3:GetBucketLogging",
    ]
  }
}
resource "aws_iam_role_policy" "master_config" {
  policy = "${data.aws_iam_policy_document.master_config.json}"
  role = "${aws_iam_role.role.id}"
}

output "arn" {
  value = "${aws_iam_role.role.arn}"
}