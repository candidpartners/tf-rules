const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-ensure-a-support-role-is-attached');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("IAM", "getPolicy", {PolicyName: "AWSSupportAccess", AttachmentCount: 1});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("IAM", "getPolicy", {PolicyName: "AWSSupportAccess", AttachmentCount: 0});

describe("The AWSSupportAccess policy should be attached to one or more roles, groups, or users.", () => {

    test("it fails", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("The AWSSupportAccess policy is not attached to any roles, groups, or users.")
    });

    test("it passes", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);