const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-no-initial-access-keys');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("IAM", "listUsers", {
    Users: [
        {
            UserName: "good.user",
            CreateDate: "2-2-2012"
        }
    ]
});
GoodAWS.Service("IAM", "listAccessKeys", {
    AccessKeyMetadata: [
        {
            UserName: "good.user",
            CreateDate: "3-2-2013"
        }
    ]
});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("IAM", "listUsers", {
    Users: [
        {
            UserName: "bad.user",
            CreateDate: "2-2-2012"
        }
    ]
});
BadAWS.Service("IAM", "listAccessKeys", {
    AccessKeyMetadata: [
        {
            UserName: "bad.user",
            CreateDate: "2-2-2012",
            AccessKeyId: "1234"
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