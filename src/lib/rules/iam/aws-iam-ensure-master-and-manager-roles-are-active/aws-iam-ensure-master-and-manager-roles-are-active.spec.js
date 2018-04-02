const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-ensure-master-and-manager-roles-are-active');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("IAM", "listRoles", {Roles: [{RoleName: "IAM_Master"}, {RoleName: "IAM_Manager"}]});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("IAM", "listRoles", {Roles: []});

describe("Master and Manager roles should be active.", () => {

    test("it fails", async () => {
        let result = await rule.livecheck({provider: BadAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("One or both of the IAM Master and IAM Manager roles are not active.")
    });

    test("it passes", async () => {
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);