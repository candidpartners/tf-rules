const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-avoid-use-of-root-account');

let csv =
`user,password_last_used
<root_account>,${(new Date(new Date().getTime() - 1000 * 60 * 60 * 24 * 2)).toDateString()}`;

let _AWS = new AWSPromiseMock();

let MockService = { IAM: {
        GetIAMCredentialReport: () => Promise.resolve(csv)
    }
};


describe("IAMAvoidUseOfRootAccount", () => {

    test("It recognizes when the root account logged in recently", async () => {
        let result = await rule.livecheck({config: 5, provider: _AWS,services:MockService});
        expect(result.valid).toBe('fail');
        expect(result.message).toBeTruthy();
    });

    test("It recognizes when the root account has not logged in recently", async () => {
        let result = await rule.livecheck({config: 2, provider: _AWS,services:MockService});
        expect(result.valid).toBe('success');
    });
}, 10000);

