'use strict';
const AWSPromiseMock = require('../../../../aws-promise-mock');
const _ = require('lodash');
const rule = require('./aws-s3-cloudtrail-bucket-access-logging-enabled');

describe('s3-cloudtrail-bucket-access-logging-enabled', function () {

    it("Fails when the CloudTrail bucket is in a different account", async () => {
        let provider = new AWSPromiseMock();
        provider.Service("CloudTrail", "describeTrails", {trailList: [{S3BucketName: "MyBucket"}]});
        provider.ServiceError("S3", "getBucketLogging", {code: "AccessDenied"});
        let result = await rule.livecheck({config: true, provider: provider});
        expect(result.valid).toBe("fail");
        expect(result.message).toBeTruthy();
    });

    it("Returns a fail", async () => {
        let provider = new AWSPromiseMock();
        provider.Service("CloudTrail", "describeTrails", {trailList: [{S3BucketName: "MyBucket"}]});
        provider.Service("S3", "getBucketLogging", {});
        let result = await rule.livecheck({config: true, provider: provider});
        expect(result.valid).toBe("fail");
        expect(result.message).toBeTruthy();
    });

    it("Returns a success", async () => {
       let provider = new AWSPromiseMock();
       provider.Service("CloudTrail", "describeTrails", {trailList: [{S3BucketName: "MyBucket"}]});
       provider.Service("S3", "getBucketLogging", {LoggingEnabled: {TargetBucket: "MyBucket"}});
       let result = await rule.livecheck({config: true, provider: provider});
       expect(result.valid).toBe("success");
    })
});