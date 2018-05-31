const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-vpc-flow-logs-are-enabled');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("EC2", "describeVpcs", {
    "Vpcs": [
        {
            "CidrBlock": "11.0.0.0/16",
            "DhcpOptionsId": "dopt-2fdf7248",
            "State": "available",
            "VpcId": "vpc-47e7963e",
            "InstanceTenancy": "default",
            "CidrBlockAssociationSet": [
                {
                    "AssociationId": "vpc-cidr-assoc-12635b79",
                    "CidrBlock": "11.0.0.0/16",
                    "CidrBlockState": {
                        "State": "associated"
                    }
                }
            ],
            "IsDefault": false
        }
    ]
});
GoodAWS.Service("EC2", "describeFlowLogs", {
    "FlowLogs": [
        {
            "ResourceId": "vpc-47e7963e",
            "FlowLogStatus": "ACTIVE"
        }
    ]
});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("EC2", "describeVpcs", {
    "Vpcs": [
        {
            "CidrBlock": "11.0.0.0/16",
            "DhcpOptionsId": "dopt-2fdf7248",
            "State": "available",
            "VpcId": "vpc-47e7963e",
            "InstanceTenancy": "default",
            "CidrBlockAssociationSet": [
                {
                    "AssociationId": "vpc-cidr-assoc-12635b79",
                    "CidrBlock": "11.0.0.0/16",
                    "CidrBlockState": {
                        "State": "associated"
                    }
                }
            ],
            "IsDefault": false
        }
    ]
});
BadAWS.Service("EC2", "describeFlowLogs", {
    "FlowLogs": [
        {
            "ResourceId": "vpc-47e7923e",
            "FlowLogStatus": "ACTIVE"
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