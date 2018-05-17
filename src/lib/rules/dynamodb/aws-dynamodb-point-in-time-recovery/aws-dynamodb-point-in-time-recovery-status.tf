provider "aws" {
  region = "us-west-2"
}

resource "aws_dynamodb_table" "basic-dynamodb-table" {
  name           = "MyTestTable"
  read_capacity  = 20
  write_capacity = 20
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  tags {
    Name        = "dynamodb-test-table"
    Environment = "development"
  }

  point_in_time_recovery {
    enabled = true
  }
}
