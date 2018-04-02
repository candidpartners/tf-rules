const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-policies-are-attached-only-to-groups-or-roles');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("IAM", "listUsers", {Users: ["User 1"]});
GoodAWS.Service("IAM", "listAttachedUserPolicies", {UserName: "User 1"});
GoodAWS.Service("IAM", "listUserPolicies", {UserName: "User 1"});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("IAM", "listUsers", {Users: ["User 1"]});
BadAWS.Service("IAM", "listAttachedUserPolicies", {});
BadAWS.Service("IAM", "listUserPolicies", {PolicyNames: ["MyPolicy"]});

describe("IAM policies are only attached to groups or roles.", () => {

    // test("it fails", async () => {
    //     let result = await rule.livecheck({provider: BadAWS});
    //     expect(result.valid).toBe('fail');
    //     expect(result.message).toBe("One or more users have policies directly attached.")
    // });

    test("it passes", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);