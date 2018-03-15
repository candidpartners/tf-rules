let rule = require('./aws-cloudtrail-ensure-s3-bucket-acl-type');

let context = {
    "config": [
        "private",
        "aws-exec-read"
    ],
    "instance": {
        "enable_log_file_validation": true,
        "enable_logging": true,
        "event_selector": [
            {
                "data_resource": [
                    {
                        "type": "AWS::S3::Object",
                        "values": [
                            "arn:aws:s3:::tf-bucket/foobar"
                        ]
                    }
                ],
                "include_management_events": false,
                "read_write_type": "All"
            }
        ],
        "include_global_service_events": false,
        "is_multi_region_trail": false,
        "name": "tf-trail-foobar",
        "s3_bucket_name": "my-bucket",
        "s3_key_prefix": "prefix"
    },
    "plan": {
        "aws_cloudtrail": {
            "foobar": {
                "enable_log_file_validation": true,
                "enable_logging": true,
                "event_selector": [
                    {
                        "data_resource": [
                            {
                                "type": "AWS::S3::Object",
                                "values": [
                                    "arn:aws:s3:::tf-bucket/foobar"
                                ]
                            }
                        ],
                        "include_management_events": false,
                        "read_write_type": "All"
                    }
                ],
                "include_global_service_events": false,
                "is_multi_region_trail": false,
                "name": "tf-trail-foobar",
                "s3_bucket_name": "my-bucket",
                "s3_key_prefix": "prefix"
            }
        },
        "aws_s3_bucket": {
            "cloudtrail_bucket": {
                "acl": "private",
                "bucket": "my-bucket",
                "force_destroy": false
            }
        }
    }
};

describe('aws-cloudtrail-ensure-s3-bucket-acl-type', () => {
    it("Will succeed if the acl is in the configured list", function () {
        const result = rule.validate(context);
        expect(result.valid).toBe('success');
    });

    it("Will fail if the acl is not in the configured list", function () {
        const configContext = Object.assign({},context,{config:['public']});
        const result = rule.validate(configContext);
        expect(result.valid).toBe('fail');
        expect(result.message).toBe(`The cloudtrail log bucket does not have a acl type of one of the following : [\"public\"]`);
    });

    it("Will succeed if the s3 bucket is not being checked in terraform", function(){
        const noS3context = Object.assign({},context);
        noS3context.plan = Object.assign({},context.plan,{
            aws_s3_bucket: {}
        });
        const result = rule.validate(noS3context);
        expect(result.valid).toBe('success');
    })
});
