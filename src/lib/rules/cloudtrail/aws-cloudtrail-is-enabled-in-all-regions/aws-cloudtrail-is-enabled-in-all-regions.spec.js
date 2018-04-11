const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-cloudtrail-is-enabled-in-all-regions');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("CloudTrail", "describeTrails", {trailList: [{IsMultiRegionTrail: true}]});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("CloudTrail", "describeTrails", {trailList: [{IsMultiRegionTrail: false}]});

describe("At least one cloudtrail must be enabled in all regions", () => {

    test("it fails", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("At least one CloudTrail resource is enabled in all regions.")
    });

    test("it passes", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);