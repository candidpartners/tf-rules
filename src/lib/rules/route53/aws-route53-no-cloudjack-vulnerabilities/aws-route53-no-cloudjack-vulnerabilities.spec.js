const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-route53-no-cloudjack-vulnerabilities');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("Route53", "listHostedZones", {
    "HostedZones": [
        {
            "Id": "/hostedzone/ZKAEAZYDAWPQ5",
            "Name": "candid.ninja.",
            "CallerReference": "RISWorkflow-RD:4675c254-fbf2-40d1-8351-d0ebe50b7aef",
            "Config": {
                "Comment": "Managed by Terraform",
                "PrivateZone": false
            },
            "ResourceRecordSetCount": 24
        }
    ]
});
GoodAWS.Service("Route53", "listResourceRecordSets", {
    "ResourceRecordSets": [
        {
            "Name": "2cyqltswevpk7pdtb5vimons5v7qackr._domainkey.candid.ninja.",
            "Type": "CNAME",
            "TTL": 1800,
            "ResourceRecords": [
                {
                    "Value": "2cyqltswevpk7pdtb5vimons5v7qackr.dkim.amazonses.com"
                }
            ]
        },
        {
            "Name": "jonathan.candid.ninja.",
            "Type": "A",
            "AliasTarget": {
                "HostedZoneId": "Z3AQBSTGFYJSTF",
                "DNSName": "s3-website-us-east-1.amazonaws.com.",
                "EvaluateTargetHealth": false
            }
        }
    ]
});

let BadCnameAWS = new AWSPromiseMock();
BadCnameAWS.Service("Route53", "listHostedZones", {
    "HostedZones": [
        {
            "Id": "/hostedzone/ZKAEAZYDAWPQ5",
            "Name": "candid.ninja.",
            "CallerReference": "RISWorkflow-RD:4675c254-fbf2-40d1-8351-d0ebe50b7aef",
            "Config": {
                "Comment": "Managed by Terraform",
                "PrivateZone": false
            },
            "ResourceRecordSetCount": 24
        }
    ]
});
BadCnameAWS.Service("Route53", "listResourceRecordSets", {
    "ResourceRecordSets": [
        {
            "Name": "2cyqltswevpk7pdtb5vimons5v7qackr._domainkey.candid.ninja.",
            "Type": "CNAME",
            "TTL": 1800,
            "ResourceRecords": [
                {
                    "Value": "2cyqltswevpk7pdtb5vimons5v7qackr.dkim.amazonses.com"
                }
            ]
        },
        {
            "Name": "go.candid.ninja.",
            "Type": "A",
            "TTL": 300,
            "ResourceRecords": [
                {
                    "Value": "52.33.25.243"
                }
            ]
        },
        {
            "Name": "jonathan.candid.ninja.",
            "Type": "A",
            "AliasTarget": {
                "HostedZoneId": "Z3AQBSTGFYJSTF",
                "DNSName": "s3-website-us-east-1.amazonaws.com.",
                "EvaluateTargetHealth": false
            }
        }
    ]
});

let BadAliasAWS = new AWSPromiseMock();
BadAliasAWS.Service("Route53", "listHostedZones", {
    "HostedZones": [
        {
            "Id": "/hostedzone/ZKAEAZYDAWPQ5",
            "Name": "candid.ninja.",
            "CallerReference": "RISWorkflow-RD:4675c254-fbf2-40d1-8351-d0ebe50b7aef",
            "Config": {
                "Comment": "Managed by Terraform",
                "PrivateZone": false
            },
            "ResourceRecordSetCount": 24
        }
    ]
});
BadAliasAWS.Service("Route53", "listResourceRecordSets", {
    "ResourceRecordSets": [
        {
            "Name": "2cyqltswevpk7pdtb5vimons5v7qackr._domainkey.candid.ninja.",
            "Type": "CNAME",
            "TTL": 1800,
            "ResourceRecords": [
                {
                    "Value": "2cyqltswevpk7pdtb5vimons5v7qackr.dkim.amazonses.com"
                }
            ]
        },
        {
            "Name": "jonathan.candid.ninja.",
            "Type": "A"
        }
    ]
});

describe("It can pass a livecheck.", () => {

    test("Bad CNAME livecheck", async () => {
        let result = await rule.livecheck({provider: BadCnameAWS});
        expect(result.valid).toBe('fail');
    });

    test("Bad Alias livecheck", async () => {
        let result = await rule.livecheck({provider: BadAliasAWS});
        expect(result.valid).toBe('fail');
    });

    test("Good livecheck", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);