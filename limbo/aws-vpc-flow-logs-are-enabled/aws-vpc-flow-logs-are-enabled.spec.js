const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-vpc-flow-logs-are-enabled');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("EC2", "describeFlowLogs", {
    FlowLogs: [
        {
            FlowLogStatus: "ACTIVE"
        }
    ]
});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("EC2", "describeFlowLogs", {
    FlowLogs: [
        {
            FlowLogStatus: "INACTIVE"
        }
    ]
});

describe("It recognizes a livecheck", () => {

    test("valid fail", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
    });

    test("valid success", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);