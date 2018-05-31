const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-vpc-routing-tables-for-vpc-peering-are-least-access');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("EC2", "describeVpcPeeringConnections", {
    "VpcPeeringConnections": [
        {
            "AccepterVpcInfo": {
                "CidrBlock": "10.0.0.0/16",
                "CidrBlockSet": [
                    {
                        "CidrBlock": "10.0.0.0/16"
                    }
                ],
                "OwnerId": "421471939647",
                "PeeringOptions": {
                    "AllowDnsResolutionFromRemoteVpc": false,
                    "AllowEgressFromLocalClassicLinkToRemoteVpc": false,
                    "AllowEgressFromLocalVpcToRemoteClassicLink": false
                },
                "VpcId": "vpc-1f2f7566",
                "Region": "us-west-2"
            },
            "RequesterVpcInfo": {
                "CidrBlock": "11.0.0.0/16",
                "CidrBlockSet": [
                    {
                        "CidrBlock": "11.0.0.0/16"
                    }
                ],
                "OwnerId": "421471939647",
                "PeeringOptions": {
                    "AllowDnsResolutionFromRemoteVpc": false,
                    "AllowEgressFromLocalClassicLinkToRemoteVpc": false,
                    "AllowEgressFromLocalVpcToRemoteClassicLink": false
                },
                "VpcId": "vpc-47e7963e",
                "Region": "us-west-2"
            },
            "Status": {
                "Code": "active",
                "Message": "Active"
            },
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "CIS rule test connection"
                }
            ],
            "VpcPeeringConnectionId": "pcx-9c2c33f5"
        }
    ]
});
GoodAWS.Service("EC2", "describeRouteTables", {
    "RouteTables": [
        {
            "Associations": [
                {
                    "Main": true,
                    "RouteTableAssociationId": "rtbassoc-af6678c9",
                    "RouteTableId": "rtb-6880760e"
                },
                {
                    "Main": false,
                    "RouteTableAssociationId": "rtbassoc-f3793f88",
                    "RouteTableId": "rtb-6880760e",
                    "SubnetId": "subnet-884c7cc0"
                },
                {
                    "Main": false,
                    "RouteTableAssociationId": "rtbassoc-9a793fe1",
                    "RouteTableId": "rtb-6880760e",
                    "SubnetId": "subnet-d792518d"
                }
            ],
            "PropagatingVgws": [],
            "RouteTableId": "rtb-6880760e",
            "Routes": [
                {
                    "DestinationCidrBlock": "172.31.0.0/16",
                    "GatewayId": "local",
                    "Origin": "CreateRouteTable",
                    "State": "active"
                },
                {
                    "DestinationCidrBlock": "11.0.0.0/16",
                    "GatewayId": "pcx-9c2c33f5",
                    "Origin": "CreateRoute",
                    "State": "active"
                }
            ],
            "Tags": [],
            "VpcId": "vpc-1f2f7566"
        }
    ]
});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("EC2", "describeVpcPeeringConnections", {
    "VpcPeeringConnections": [
        {
            "AccepterVpcInfo": {
                "CidrBlock": "10.0.0.0/16",
                "CidrBlockSet": [
                    {
                        "CidrBlock": "10.0.0.0/16"
                    }
                ],
                "OwnerId": "421471939647",
                "PeeringOptions": {
                    "AllowDnsResolutionFromRemoteVpc": false,
                    "AllowEgressFromLocalClassicLinkToRemoteVpc": false,
                    "AllowEgressFromLocalVpcToRemoteClassicLink": false
                },
                "VpcId": "vpc-1f2f7566",
                "Region": "us-west-2"
            },
            "RequesterVpcInfo": {
                "CidrBlock": "11.0.0.0/16",
                "CidrBlockSet": [
                    {
                        "CidrBlock": "11.0.0.0/16"
                    }
                ],
                "OwnerId": "421471939647",
                "PeeringOptions": {
                    "AllowDnsResolutionFromRemoteVpc": false,
                    "AllowEgressFromLocalClassicLinkToRemoteVpc": false,
                    "AllowEgressFromLocalVpcToRemoteClassicLink": false
                },
                "VpcId": "vpc-47e7963e",
                "Region": "us-west-2"
            },
            "Status": {
                "Code": "active",
                "Message": "Active"
            },
            "Tags": [
                {
                    "Key": "Name",
                    "Value": "CIS rule test connection"
                }
            ],
            "VpcPeeringConnectionId": "pcx-9c2c33f5"
        }
    ]
});
BadAWS.Service("EC2", "describeRouteTables", {
    "RouteTables": [
        {
            "Associations": [
                {
                    "Main": true,
                    "RouteTableAssociationId": "rtbassoc-af6678c9",
                    "RouteTableId": "rtb-6880760e"
                },
                {
                    "Main": false,
                    "RouteTableAssociationId": "rtbassoc-f3793f88",
                    "RouteTableId": "rtb-6880760e",
                    "SubnetId": "subnet-884c7cc0"
                },
                {
                    "Main": false,
                    "RouteTableAssociationId": "rtbassoc-9a793fe1",
                    "RouteTableId": "rtb-6880760e",
                    "SubnetId": "subnet-d792518d"
                }
            ],
            "PropagatingVgws": [],
            "RouteTableId": "rtb-6880760e",
            "Routes": [
                {
                    "DestinationCidrBlock": "172.31.0.0/16",
                    "GatewayId": "local",
                    "Origin": "CreateRouteTable",
                    "State": "active"
                },
                {
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": "test",
                    "Origin": "CreateRoute",
                    "State": "active"
                }
            ],
            "Tags": [],
            "VpcId": "vpc-c385cba4"
        }
    ]
});

describe("It does a livecheck", () => {

    test("It fails", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
    });

    test("It passes", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);