const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-s3-cloudtrail-bucket-is-not-publicly-accessible');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("CloudTrail", "describeTrails", {trailList: [{S3BucketName: "MyBucket"}]});
GoodAWS.Service("S3", "getBucketPolicy", {Policy: {Statement: {Effect: "Deny", Principal: "*"}}});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("CloudTrail", "describeTrails", {trailList: [{S3BucketName: "MyBucket"}]});
BadAWS.Service("S3", "getBucketPolicy", {Policy: {Statement: {Effect: "Allow", Principal: "*"}}});

describe("The CloudTrail S3 logging bucket should not be publicly accessible.", () => {

    test("it fails", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("One or more CloudTrail S3 buckets is publicly accessible.")
    });

    test("it passes", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);