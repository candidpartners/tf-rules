const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-vpc-default-security-group-restricts-all-traffic');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("EC2", "describeSecurityGroups", {
    SecurityGroups: [
        {
            GroupName: "default",
            IpPermissions: [],
            IpPermissionsEgress: [],
            VpcId: "testVpc"
        }
    ]
});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("EC2", "describeSecurityGroups", {
    SecurityGroups: [
        {
            GroupName: "default",
            IpPermissions: [
                "inboundRule"
            ],
            IpPermissionsEgress: [
                "outboundRule"
            ],
            VpcId: "testVpc"
        }
    ]
});

describe("Recognizes a livecheck", () => {

    test("bad livecheck", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
    });

    test("good livecheck", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);