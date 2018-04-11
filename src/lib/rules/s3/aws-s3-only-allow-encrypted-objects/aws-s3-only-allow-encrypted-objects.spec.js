const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-s3-only-allow-encrypted-objects');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("S3", "listBuckets", {Buckets: [{Name: "my-bucket"}]});
GoodAWS.Service("S3", "getBucketPolicy", {
        "Policy": "{\"Version\":\"2012-10-17\",\"Id\":\"PutObjPolicy\",\"Statement\":[{\"Sid\":\"DenyIncorrectEncryptionHeader\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::my-bucket/*\",\"Condition\":{\"StringNotEquals\":{\"s3:x-amz-server-side-encryption\":\"AES256\"}}},{\"Sid\":\"DenyUnEncryptedObjectUploads\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::ethan-encryption-test/*\",\"Condition\":{\"Null\":{\"s3:x-amz-server-side-encryption\":\"true\"}}}]}"
    }
)

let BadAWS = new AWSPromiseMock();
BadAWS.Service("S3", "listBuckets", {Buckets: [{Name: "my-bucket"}]});
BadAWS.Service("S3", "getBucketPolicy", {
    "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity E3LBOP92C3U0CI\"},\"Action\":[\"s3:PutObject\",\"s3:GetObject\"],\"Resource\":[\"arn:aws:s3:::my-bucket/tmp/*\",\"arn:aws:s3:::volker-dev-static/appCodes/*\"]}]}"
});

jest.setTimeout(10000);

describe("aws-s3-only-allow-encrypted-objects", () => {

    test("It recognizes an invalid s3 bucket", async () => {
        let result = await rule.livecheck({config: {AllowAES256:true}, provider: BadAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBeTruthy();
    });

    test("It recognizes a valid s3 bucket", async () => {
        let result = await rule.livecheck({config: {AllowAES256:true}, provider: GoodAWS});
        expect(result.valid).toBe('success');
    });

}, 10000);