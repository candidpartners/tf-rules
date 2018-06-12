// @flow
'use strict';
const debug = require('debug')('snitch/s3-encryption');
const _ = require('lodash');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const S3Encryption = {};

S3Encryption.uuid = "25f03a5c-7db0-4428-a8ff-efb9f7003064";
S3Encryption.groupName = "S3";
S3Encryption.tags = [["Candid", "1.0", "13"]];
S3Encryption.config_triggers = ["AWS::S3::Bucket"];
S3Encryption.paths = {S3Encryption: "aws_s3_bucket"};
S3Encryption.docs = {
    description: 'All non-excluded S3 buckets are encrypted.',
    recommended: true
};
S3Encryption.schema = {
    type: 'object',
    properties: {
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
    let reqTags = config;

    let buckets = await s3.listBuckets().promise();
    let bucketNames = _.flatMap(buckets.Buckets, "Name");

    let promises = bucketNames.map(x => {
        return s3.getBucketEncryption({Bucket: x}).promise()
            .then(result => ({bucket:x, status: "success", result}))
            .catch(error => ({bucket:x, status: "fail", error}))
    });

    let AllBuckets = await Promise.all(promises);
    let isUnencrypted = x => x.status === 'fail' && x.error.code === 'ServerSideEncryptionConfigurationNotFoundError'
    let UnencryptedBuckets  = AllBuckets.filter(isUnencrypted);

    return new RuleResult({
        valid: (UnencryptedBuckets.length > 0) ? "fail" : "success",
        message: "S3 Buckets must be encrypted",
        resources: AllBuckets.map(x => {
            let unencrypted = isUnencrypted(x);

            return new Resource({
                is_compliant: unencrypted ? false : true,
                resource_id: x.bucket,
                resource_type: "AWS::S3::Bucket",
                message: unencrypted ? `is unencrypted.` : "is encrypted."
            })
        })
    })
};

S3Encryption.paths = {
    S3: 'aws_s3_bucket'
};

S3Encryption.validate = async function(context /*: Context */) {
    let {config,provider,instance} = context;

    let server_side_encryption_array = _.get(instance,'server_side_encryption_configuration',[]);
    let isEncrypted = server_side_encryption_array.find(x => x.rule);

    if(isEncrypted){
        return {valid: 'success'}
    }
    else {
        return {
            valid: 'fail',
            resource_type: "AWS::S3::Bucket",
            message: "A S3 bucket is not encrypted."
        }
    }
};

module.exports = S3Encryption;

