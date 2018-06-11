const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-ensure-specified-groups-and-roles-exist');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("IAM", "listGroups", {
    "Groups": [
        {
            "Path": "/",
            "GroupName": "Administrators",
            "GroupId": "AGPAITBPVKFYO2Q6PVUUS",
            "Arn": "arn:aws:iam::421471939647:group/Administrators",
            "CreateDate": "2017-03-26T01:31:15Z"
        },
        {
            "Path": "/",
            "GroupName": "Volker.UI",
            "GroupId": "AGPAIUO6WYTCASR56ZGJQ",
            "Arn": "arn:aws:iam::421471939647:group/SecureUsers",
            "CreateDate": "2017-12-06T14:32:21Z"
        }
    ]
});

GoodAWS.Service("IAM", "listRoles", {
    "Roles": [
        {
            "Path": "/",
            "RoleName": "Admin-Role",
            "RoleId": "AROAJUDMPQ4WQFKDQCZUS",
            "Arn": "arn:aws:iam::421471939647:role/Admin-Role",
            "CreateDate": "2017-12-04T19:15:12Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": [
                                "lambda.amazonaws.com",
                                "apigateway.amazonaws.com",
                                "edgelambda.amazonaws.com"
                            ]
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "Description": "Used for troubleshooting",
            "MaxSessionDuration": 3600
        },
        {
            "Path": "/",
            "RoleName": "Admin_Role",
            "RoleId": "AROAJHXHX6X5T7N3PRQMK",
            "Arn": "arn:aws:iam::421471939647:role/Admin_Role",
            "CreateDate": "2017-12-18T17:21:45Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::421471939647:root"
                        },
                        "Action": "sts:AssumeRole",
                        "Condition": {}
                    }
                ]
            },
            "MaxSessionDuration": 3600
        }
    ]
});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("IAM", "listGroups", {
    "Groups": [
        {
            "Path": "/",
            "GroupName": "Administrators",
            "GroupId": "AGPAITBPVKFYO2Q6PVUUS",
            "Arn": "arn:aws:iam::421471939647:group/Administrators",
            "CreateDate": "2017-03-26T01:31:15Z"
        },
        {
            "Path": "/",
            "GroupName": "Test",
            "GroupId": "AGPAIUO6WYTCASR56ZGJQ",
            "Arn": "arn:aws:iam::421471939647:group/SecureUsers",
            "CreateDate": "2017-12-06T14:32:21Z"
        }
    ]
});

BadAWS.Service("IAM", "listRoles", {
    "Roles": [
        {
            "Path": "/",
            "RoleName": "Admin-Role",
            "RoleId": "AROAJUDMPQ4WQFKDQCZUS",
            "Arn": "arn:aws:iam::421471939647:role/Admin-Role",
            "CreateDate": "2017-12-04T19:15:12Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "Service": [
                                "lambda.amazonaws.com",
                                "apigateway.amazonaws.com",
                                "edgelambda.amazonaws.com"
                            ]
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            },
            "Description": "Used for troubleshooting",
            "MaxSessionDuration": 3600
        },
        {
            "Path": "/",
            "RoleName": "Admin_Role",
            "RoleId": "AROAJHXHX6X5T7N3PRQMK",
            "Arn": "arn:aws:iam::421471939647:role/Admin_Role",
            "CreateDate": "2017-12-18T17:21:45Z",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::421471939647:root"
                        },
                        "Action": "sts:AssumeRole",
                        "Condition": {}
                    }
                ]
            },
            "MaxSessionDuration": 3600
        }
    ]
});

describe("It passes a livecheck", () => {

    test("It fails", async () => {
        let result = await rule.livecheck({config: {groups: ["Administrators", "Volker.UI"], roles: ["Admin-Role", "Admin_Role"]}, provider: BadAWS});
        expect(result.valid).toBe('fail');
    });

    test("It passes", async () => {
        let result = await rule.livecheck({config: {groups: ["Administrators", "Volker.UI"], roles: ["Admin-Role", "Admin_Role"]}, provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);