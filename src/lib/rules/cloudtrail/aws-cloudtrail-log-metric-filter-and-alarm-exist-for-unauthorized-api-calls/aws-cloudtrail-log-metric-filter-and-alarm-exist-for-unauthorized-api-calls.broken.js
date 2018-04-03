const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-cloudtrail-log-metric-filter-and-alarm-exist-for-unauthorized-api-calls');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("CloudTrail", "describeTrails", {});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("CloudTrail", "describeTrails", {});

describe("A log metric filter and alarm exist for unauthorized API calls.", () => {

    test("it fails", async () => {
        let result = await rule.livecheck({provider: AWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("A log metric filter and alarm do not exist for unauthorized API calls.")
    });

    test("it passes", async () => {
        let result = await rule.livecheck({provider: AWS});
        expect(result.valid).toBe('success');
    });
}, 10000);