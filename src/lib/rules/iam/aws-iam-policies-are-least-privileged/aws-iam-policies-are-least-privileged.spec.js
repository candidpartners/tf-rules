const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-policies-are-least-privileged');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("IAM", "listPolicies", {
    Policies: [
        {
            "PolicyName": "testPolicy",
            "Arn": "arn:aws:iam::aws:policy/testPolicy",
            "DefaultVersionId": "v1",
        }
    ]
});
GoodAWS.Service("IAM", "getPolicyVersion", {
    "PolicyVersion": {
        "Document": '"Statement": ["Sid": "CloudWatchEventsFullAccess","Effect": "Allow","Action": "events:*","Resource": "*"},{"Sid": "IAMPassRoleForCloudWatchEvents","Effect": "Allow","Action": "iam:PassRole","Resource": "arn:aws:iam::*:role/AWS_Events_Invoke_Targets"',
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2016-01-14T18:37:08Z"
    }
});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("IAM", "listPolicies", {
    Policies: [
        {
            "PolicyName": "testPolicy",
            "Arn": "arn:aws:iam::aws:policy/testPolicy",
            "DefaultVersionId": "v1",
        }
    ]
});
BadAWS.Service("IAM", "getPolicyVersion", {
    "PolicyVersion": {
        "Document": '"Version": "2012-10-17", "Statement": [ { "Sid": "CloudWatchEventsFullAccess","Effect": "Allow","Action": "*","Resource": "*"}{"Sid": "IAMPassRoleForCloudWatchEvents","Effect": "Allow","Action": "iam:PassRole","Resource": "arn:aws:iam::*:role/AWS_Events_Invoke_Targets"}]',
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2016-01-14T18:37:08Z"
    }
});

describe("it recognizes a live check", () => {

    test("bad livecheck", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
    });

    test("good livecheck", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);