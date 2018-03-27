provider "aws" {
  region = "us-west-2"
}

data "external" "npm_install" {
  program = ["node", "npm_install.js"]
}

data "archive_file" "lambda_code" {
  depends_on = ["data.external.npm_install"]
  source_dir = "${path.module}/src"
  type = "zip"
  output_path = "${path.module}/function.zip"
}

data "aws_region" "current" {}
module "snitch" {
  source = "modules/snitch"
  env = "${data.aws_region.current.name}"
  source_code_hash = "${data.archive_file.lambda_code.output_base64sha256}"
  zip_path = "${data.archive_file.lambda_code.output_path}"
}

