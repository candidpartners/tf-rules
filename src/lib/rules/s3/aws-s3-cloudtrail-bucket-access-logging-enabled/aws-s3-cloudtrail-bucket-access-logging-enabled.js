'use strict';
const debug = require('debug')('snitch/s3-bucket-logging');
const co = require('co');
const _ = require('lodash');
const {NonCompliantResource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const S3CloudTrailBucketAccessLoggingEnabled = {};

S3CloudTrailBucketAccessLoggingEnabled.uuid = "e6f0f199-1b03-4fe6-8def-ce7c69852c69";
S3CloudTrailBucketAccessLoggingEnabled.groupName = "S3";
S3CloudTrailBucketAccessLoggingEnabled.tags = ["CIS | 1.1.0 | 2.6"];
S3CloudTrailBucketAccessLoggingEnabled.config_triggers = ["AWS::S3::Bucket"];
S3CloudTrailBucketAccessLoggingEnabled.paths = {S3Encryption: "aws_s3_bucket"};
S3CloudTrailBucketAccessLoggingEnabled.docs = {
    description: 'Access logging is enabled on the CloudTrail S3 bucket.',
    recommended: true
};
S3CloudTrailBucketAccessLoggingEnabled.schema = {type: 'boolean', default: true};

S3CloudTrailBucketAccessLoggingEnabled.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;

    let s3 = new provider.S3();
    let cloud = new provider.CloudTrail();
    let trail = yield cloud.describeTrails().promise();
    let list = trail.trailList;
    let buckets = list.map(x => x.S3BucketName);

    try {
        let logs = yield buckets.map(x => s3.getBucketLogging({Bucket: x}).promise());
        let enabledBuckets = logs.filter(x => x.hasOwnProperty("LoggingEnabled"));

        if (enabledBuckets.length !== logs.length) {
            let disabledBuckets = logs.filter(x => !x.hasOwnProperty("LoggingEnabled"));
            let noncompliant_resources = disabledBuckets.map(x => {
                return new NonCompliantResource({
                    resource_id: x,
                    resource_type: "AWS::S3::Bucket",
                    message: "does not have logging enabled"
                })
            });
            return new RuleResult({
                valid: "fail",
                message: "One or more of your CloudTrail S3 buckets does not have logging enabled.",
                noncompliant_resources
            })
        }
        else {
            return new RuleResult({valid: "success"})
        }

    // Thrown if the CloudTrail S3 bucket is in a different account than Snitch is being run in.
    } catch (err) {
        if (err.code === 'AccessDenied') {
            return new RuleResult({
                valid: "fail",
                message: "Snitch does not have access to the CloudTrail S3 bucket from this account.",
                noncompliant_resources: [new NonCompliantResource({
                    resource_id: "Permission Error",
                    resource_type: "AWS::::Account",
                    message: "Snitch does not have access to the CloudTrail S3 bucket from this account."
                })]
            })
        }
    }
});

module.exports = S3CloudTrailBucketAccessLoggingEnabled;