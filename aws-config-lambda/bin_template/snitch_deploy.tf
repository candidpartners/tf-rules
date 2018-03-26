provider "aws" {
  region = "us-west-2"
}

//data "archive_file" "lambda_code" {
//  source_dir = "${path.module}/../src"
//  type = "zip"
//  output_path = "${path.module}/function.zip"
//}

module "snitch" {
  source = "./snitch_module"
  env = "dev"
  source_code_hash = "${base64sha256(file("function.zip"))}"
  zip_path = "function.zip"
}