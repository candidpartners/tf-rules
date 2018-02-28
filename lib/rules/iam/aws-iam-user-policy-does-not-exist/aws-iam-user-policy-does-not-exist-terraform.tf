provider "aws" {
  region = "us-east-1"
}

resource "aws_iam_user" "user" {
  name = "test-user"
}


data "aws_iam_policy" "example" {
  arn = "arn:aws:iam::123456789012:policy/UsersManageOwnCredentials"
}

resource "aws_iam_user_policy_attachment" "test-attach" {
  user       = "${aws_iam_user.user.name}"
  policy_arn = "${data.aws_iam_policy.example.arn}"
}