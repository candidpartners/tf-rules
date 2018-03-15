provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "my_vpc" {
  cidr_block = "1.0.0.0/16"
}

module "my_flow_low" {
  source = "vpc-module"
  vpc_id = "${aws_vpc.my_vpc.id}"
}

