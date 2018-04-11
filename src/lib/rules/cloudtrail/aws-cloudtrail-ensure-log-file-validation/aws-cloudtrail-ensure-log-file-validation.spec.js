const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-cloudtrail-ensure-log-file-validation');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("CloudTrail", "describeTrails", {trailList: [{LogFileValidationEnabled: true}]});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("CloudTrail", "describeTrails", {trailList: [{LogFileValidationEnabled: false}]});

describe("All CloudTrail resources should have log file validation enabled.", () => {

    test("it fails", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBeTruthy();
    });

    test("it passes", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);