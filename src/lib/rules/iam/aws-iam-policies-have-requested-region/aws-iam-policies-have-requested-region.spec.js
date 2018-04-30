const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-policies-have-requested-region');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("IAM", "listPolicies", {
    Policies: [
        {
            "PolicyName": "TestPolicy",
            "Arn": "arn:aws:iam::aws:policy/TestPolicy",
            "DefaultVersionId": "v1",
        }
    ]
});
GoodAWS.Service("IAM", "getPolicyVersion", {
    "PolicyVersion": {
        "Document": '"Condition": {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},"VersionId": "v1","IsDefaultVersion": true,"CreateDate": "2016-01-14T18:37:08Z"'
    }
});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("IAM", "listPolicies", {
    Policies: [
        {
            "PolicyName": "TestPolicy",
            "Arn": "arn:aws:iam::aws:policy/TestPolicy",
            "DefaultVersionId": "v1",
        }
    ]
});
BadAWS.Service("IAM", "getPolicyVersion", {
    "PolicyVersion": {
        "Document": '"VersionId": "v1","IsDefaultVersion": true,"CreateDate": "2016-01-14T18:37:08Z"'
    }
});

describe("It passes a livecheck.", () => {

    test("Bad livecheck", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
    });

    test("Good livecheck", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);