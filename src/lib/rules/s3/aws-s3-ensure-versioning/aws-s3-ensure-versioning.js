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
    let bucketlist = buckets.Buckets
    let bucketNames = bucketlist.map(x => x.Name)

    let firstBucket = bucketNames[0]

    function getBucketVersioning(bucketName){
        var params = {
            Bucket: bucketName
        }
       return s3.getBucketVersioning(params).promise()
    }
    let versionings = bucketNames.map(x => getBucketVersioning(x))
    let versioningResults = await Promise.all(versionings);

    let resultArray = []
    for(let i = 0; i < versioningResults.length; i++){
        let bucketname = bucketNames[i]
        let versionResult = versioningResults[i]
        let result = {
            bucket: bucketname, 
            version: versionResult
        }
        resultArray.push(result)
    }

    let isInvalid = resultArray.some(x => x.version.Status)
    return new RuleResult({
        valid: !isInvalid ? "success" : "fail", 
        message: "S3 Buckets must have versioning",
        resources: resultArray.map(x => {
            let hasVersioning = x.version.Status;

            return new Resource({
                is_compliant: hasVersioning ? true : false,
                resource_id: x.bucket,
                resource_type: "AWS::S3::Bucket",
                message: hasVersioning ? `has versioning.` : "does not have versioning"
            })
        })
    })
};

S3Encryption.paths = {
    S3: 'aws_s3_bucket'
};

module.exports = S3Encryption;

