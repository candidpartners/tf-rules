provider "aws" {
  region = "us-east-1"
}

resource "aws_kms_key" "my_key" {
  description             = "KMS key 1"
  deletion_window_in_days = 10
  enable_key_rotation = true
}