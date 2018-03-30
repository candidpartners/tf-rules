'use strict';
const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const _ = require('lodash');
const rule = require('./aws-s3-cloudtrail-bucket-access-logging-enabled');

describe('s3-cloudtrail-bucket-access-logging-enabled', function () {

    it("Fails when the CloudTrail bucket is in a different account", async () => {
        let provider = new AWSPromiseMock();
        provider.Service("CloudTrail", "describeTrails", {});
        provider.Service("S3", "getBucketLoogging", {Bucket: ""});
        let result = await rule.livecheck({config: true, provider: AWS});
        expect(result.valid).toBe("fail");
        expect(result.message).toBe("Snitch does not have access to the CloudTrail S3 bucket from this account.")
    });

    it("Returns a fail", async () => {
        let provider = new AWSPromiseMock();
        provider.Service("CloudTrail", "describeTrails", {trailList: [{S3BucketName: "MyBucket"}]});
        provider.Service("S3", "getBucketLogging", {});
        let result = await rule.livecheck({config: true, provider: provider});
        expect(result.valid).toBe("fail");
        expect(result.message).toBe("One or more of your CloudTrail S3 buckets does not have logging enabled.")
    });

    it("Returns a success", async () => {
       let provider = new AWSPromiseMock();
       provider.Service("CloudTrail", "describeTrails", {trailList: [{S3BucketName: "MyBucket"}]});
       provider.Service("S3", "getBucketLogging", {LoggingEnabled: {TargetBucket: "MyBucket"}});
       let result = await rule.livecheck({config: true, provider: provider});
       expect(result.valid).toBe("success");
    })
});