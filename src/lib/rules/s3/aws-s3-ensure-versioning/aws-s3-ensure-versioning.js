'use strict';
const debug = require('debug')('snitch/s3-encryption');
const _ = require('lodash');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const S3Encryption = {};

S3Encryption.uuid = "875dcd25-644a-4ffd-831d-003e7a41090c";
S3Encryption.groupName = "S3";
S3Encryption.tags = [["Candid", "1.0", "9"]];
S3Encryption.config_triggers = ["AWS::S3::Bucket"];
S3Encryption.paths = {S3Encryption: "aws_s3_bucket"};
S3Encryption.docs = {
    description: 'Ensures S3 buckets have versioning',
    recommended: true
};
S3Encryption.schema = {
    type: 'object',
    properties: {
        enabled: {type: "boolean", title: "Enabled", default: true},
        exclude: {
            type: "array",
            items: {
                type: "string"
            }
        }
    }
};

S3Encryption.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;
    let exclude = config.exclude || [];
    let s3 = new provider.S3();
    let buckets = await s3.listBuckets().promise();
    let invalid_buckets = [];

    for (let i = 0; i < buckets.Buckets.length; i++) {
        let versioning = await s3.getBucketVersioning({Bucket: buckets.Buckets[i].Name}).promise();
        if (versioning.Status !== "Enabled") {
            invalid_buckets.push(buckets.Buckets[i].Name)
        }
    }

    return new RuleResult({
        valid: (invalid_buckets.length > 0) ? "fail" : "success",
        message: "S3 Buckets must have versioning",
        resources: buckets.Buckets.map(x => {
            let is_invalid = invalid_buckets.find(y => y === x.Name);

            return new Resource({
                is_compliant: is_invalid ? false : true,
                resource_id: x.Name,
                resource_type: "AWS::S3::Bucket",
                message: is_invalid ? "does not have versioning enabled." : `has versioning enabled.`
            })
        })
    })
};

S3Encryption.paths = {
    S3: 'aws_s3_bucket'
};

module.exports = S3Encryption;

