provider "aws" {
  region = "us-east-1"
}

resource "aws_cloudtrail" "foobar" {
  name                          = "tf-trail-foobar"
  s3_bucket_name                = "my-bucket"
  s3_key_prefix                 = "prefix"
  include_global_service_events = false

//  enable_log_file_validation = false

  event_selector {
    read_write_type = "All"
    include_management_events = false
    data_resource {
      type = "AWS::S3::Object"
      values = [
        "arn:aws:s3:::tf-bucket/foobar",
      ]
    }
  }
}