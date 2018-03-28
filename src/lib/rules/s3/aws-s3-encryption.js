'use strict';
const debug = require('debug')('snitch/s3-encryption');
const co = require('co');
const _ = require('lodash');
const {NonCompliantResource, RuleResult} = require('../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const S3Encryption = {};

S3Encryption.uuid = "25f03a5c-7db0-4428-a8ff-efb9f7003064";
S3Encryption.groupName = "S3";

S3Encryption.docs = {
    description: 'All non-excluded S3 buckets must be encrypted.',
    recommended: true
};

S3Encryption.config_triggers = ["AWS::S3::Bucket"];

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

S3Encryption.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let exclude = config.exclude || [];

    let s3 = new provider.S3();
    let reqTags = config;

    let buckets = yield s3.listBuckets().promise();
    let bucketNames = _.flatMap(buckets.Buckets, "Name");

    let promises = bucketNames.map(x => {
        return s3.getBucketEncryption({Bucket: x}).promise()
            .then(result => ({bucket:x, status: "success", result}))
            .catch(error => ({bucket:x, status: "fail", error}))
    });

    let UnencryptedBuckets = yield Promise.all(promises)
        .then(results => {
            return results.filter(x => x.status === 'fail' && x.error.code === 'ServerSideEncryptionConfigurationNotFoundError')
        });

    if (UnencryptedBuckets.length > 0) {
        let noncompliant_resources = UnencryptedBuckets.map(bucket => {
            return new NonCompliantResource({
                resource_id: bucket.bucket,
                resource_type: "AWS::S3::Bucket",
                message: `is unencrypted`
            })
        });
        return new RuleResult({
            valid: "fail",
            message: "One or more S3 buckets are not encrypted.",
            noncompliant_resources
        })
    }
    else {
        return {valid: "success"}
    }
});

S3Encryption.paths = {
    S3: 'aws_s3_bucket'
};

S3Encryption.validate = function* (context) {
    let {config,provider,instance} = context;

    let server_side_encryption_array = _.get(instance,'server_side_encryption_configuration',[]);
    let isEncrypted = server_side_encryption_array.find(x => x.rule);
    console.log(isEncrypted)

    if(isEncrypted){
        return {valid: 'success'}
    }
    else {
        return {
            valid: 'fail',
            resource_type: "AWS::S3::Bucket",
            message: "A S3 bucket is not encrypted"
        }
    }
};

module.exports = S3Encryption;

