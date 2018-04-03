const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-cloudtrail-trails-are-integrated-with-cloudwatch-logs');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("CloudTrail", "describeTrails", {trailList: [{Name: "MyTrail1"}]});
GoodAWS.Service("CloudTrail", "getTrailStatus", {LatestCloudWatchLogsDeliveryTime: new Date()});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("CloudTrail", "describeTrails", {trailList: [{Name: "MyTrail2"}]});
BadAWS.Service("CloudTrail", "getTrailStatus", {LatestCloudWatchLogsDeliveryTime: "2018-03-03T13:33:45.486Z"});

describe("All CloudTrail trails are integrated with CloudWatch logs.", () => {

    test("it fails", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("One or more CloudTrail trails are not integrated with CloudWatch logs.")
    });

    test("it passes", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);