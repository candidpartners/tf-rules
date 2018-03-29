const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-avoid-use-of-root-account');

let csv =
`user,password_last_used
<root_account>,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 2)).toDateString()}`;

let _AWS = new AWSPromiseMock();
let content = {
    "Content": csv,
    "GeneratedTime": "2018-03-01T15:28:51Z",
    "ReportFormat": "text/csv"
};

_AWS.Service("IAM", "generateCredentialReport", {"State": "COMPLETE"});
_AWS.Service("IAM", "getCredentialReport", content);

describe("IAM_AVOID_USE_OF_ROOT_ACCOUNT", () => {

    test("It recognizes when the root account logged in recently", async () => {
        let result = await rule.livecheck({provider: _AWS}, 5);
        expect(result.valid).toBe('fail');
        expect(result.message.includes(`Requires <root_account> to not have logged in during the past 5 days.`)).toBeTruthy()
    });

    test("It recognizes when the root account has not logged in recently", async () => {
        let result = await rule.livecheck({provider: _AWS}, 2);
        expect(result.valid).toBe('success');
    });
}, 10000);

