// @flow
'use strict';
const debug = require('debug')('snitch/s3-bucket-logging');
const _ = require('lodash');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const S3CloudTrailBucketAccessLoggingEnabled = {};

S3CloudTrailBucketAccessLoggingEnabled.uuid = "e6f0f199-1b03-4fe6-8def-ce7c69852c69";
S3CloudTrailBucketAccessLoggingEnabled.groupName = "S3";
S3CloudTrailBucketAccessLoggingEnabled.tags = [["CIS", "1.1.0", "2.6"]];
S3CloudTrailBucketAccessLoggingEnabled.config_triggers = ["AWS::S3::Bucket"];
S3CloudTrailBucketAccessLoggingEnabled.paths = {S3Encryption: "aws_s3_bucket"};
S3CloudTrailBucketAccessLoggingEnabled.docs = {
    description: 'Access logging is enabled on the CloudTrail S3 bucket.',
    recommended: true
};
S3CloudTrailBucketAccessLoggingEnabled.schema = {
    type: 'object',
    properties: {}
};

S3CloudTrailBucketAccessLoggingEnabled.livecheck = async function (context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;

    let s3 = new provider.S3();
    let cloud = new provider.CloudTrail();
    let trail = await cloud.describeTrails().promise();
    let list = trail.trailList;
    let buckets = list.map(x => x.S3BucketName);

    try {
        let logs = await Promise.all(buckets.map(x => s3.getBucketLogging({Bucket: x}).promise()));
        let enabledBuckets = logs.filter(x => x.hasOwnProperty("LoggingEnabled"));

        return new RuleResult({
            valid: (enabledBuckets.length === logs.length) ? "success" : "fail",
            message: "S3 Buckets should have logging enabled",
            resources: logs.map(x => {
                let isLoggingEnabled = x.hasOwnProperty("LoggingEnabled");
                return new Resource({
                    is_compliant: isLoggingEnabled ? true : false,
                    resource_id: x,
                    resource_type: "AWS::S3::Bucket",
                    message: isLoggingEnabled ? "has logging enabled." : "does not have logging enabled."
                })
            })
        });

        // Thrown if the CloudTrail S3 bucket is in a different account than Snitch is being run in.
    } catch (err) {
        return new RuleResult({
            valid: "fail",
            message: "Snitch encountered an error",
            resources: [new Resource({
                is_compliant: false,
                resource_id: "Permission Error",
                resource_type: "AWS::::Account",
                message: err.message
            })]
        })
    }
};

module.exports = S3CloudTrailBucketAccessLoggingEnabled;