const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-avoid-use-of-root-account');

let csv =
`user,password_last_used
<root_account>,${(new Date(new Date().getTime() - 1000 * 60 * 60 * 24 * 2)).toDateString()}`;

let _AWS = new AWSPromiseMock();
let content = {
    "Content": csv,
    "GeneratedTime": "2018-03-01T15:28:51Z",
    "ReportFormat": "text/csv"
};

_AWS.Service("IAM", "generateCredentialReport", {"State": "COMPLETE"});
_AWS.Service("IAM", "getCredentialReport", content);

describe("IAMAvoidUseOfRootAccount", () => {

    test("It recognizes when the root account logged in recently", async () => {
        let result = await rule.livecheck({config: 5, provider: _AWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe(`<root_account> logged in 3 days ago.`)
    });

    test("It recognizes when the root account has not logged in recently", async () => {
        let result = await rule.livecheck({config: 2, provider: _AWS});
        expect(result.valid).toBe('success');
    });
}, 10000);

