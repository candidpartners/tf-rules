const AWS = require('aws-sdk');
const AWSMock = require('../../../../aws-promise-mock');
let rule = require('./aws-cloudtrail-logs-are-encrypted');

describe("aws-cloudtrail-logs-are-encrypted", () => {

    let provider1 = new AWSMock();
    provider1.Service("CloudTrail", "describeTrails", {trailList: [{TrailARN: "arn1"}]});

    let provider2 = new AWSMock();
    provider2.Service("CloudTrail", "describeTrails", {trailList: [{KmsKeyId: "my_key_arn", TrailARN: "arn"}]});

    it("Will fail if logs are not encrypted",async () => {
        const result = await rule.livecheck({config: true, provider: provider1});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('One or more CloudTrail logs are not encrypted.');
    });

    it("Will succeed if logs are encrypted", async () => {
        const result = await rule.livecheck({config: true, provider: provider2});
        expect(result.valid).toBe('success');
    });
});