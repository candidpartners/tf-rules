provider "aws" {
  region = "us-west-2"
}

resource "aws_ebs_volume" "example" {
  availability_zone = "us-west-2"
  size = 40
  encrypted = true
  tags {
    Name = "HelloWorld"
  }
}