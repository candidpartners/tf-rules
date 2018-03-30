const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-no-root-account-access-key-exists');

let csv1 =
    `user,password_last_used,access_key_1_active,access_key_2_active
<root_account>,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 2)).toDateString()},true, false`;

let csv2 =
    `user,password_last_used,access_key_1_active,access_key_2_active
<root_account>,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 2)).toDateString()},false,false`;

let content1 = {
    "Content": csv1,
    "GeneratedTime": "2018-03-01T15:28:51Z",
    "ReportFormat": "text/csv"
};
let content2 = {
    "Content": csv2,
    "GeneratedTime": "2018-03-01T15:28:51Z",
    "ReportFormat": "text/csv"
};

let _AWS1 = new AWSPromiseMock();
_AWS1.Service("IAM", "generateCredentialReport", {"State": "COMPLETE"});
_AWS1.Service("IAM", "getCredentialReport", content1);

let _AWS2 = new AWSPromiseMock();
_AWS2.Service("IAM", "generateCredentialReport", {"State": "COMPLETE"});
_AWS2.Service("IAM", "getCredentialReport", content2);

describe("IAMNoRootAccountAccessKeyExists", () => {

    test("It recognizes when the root account still has an access key.", async () => {
        let result = await rule.livecheck({provider: _AWS1});
        expect(result.valid).toBe('fail');
        expect(result.message.includes(`One or both of the root user access keys are still in use.`)).toBeTruthy()
    });

    test("It recognizes when the root account does not have an access key.", async () => {
        let result = await rule.livecheck({provider: _AWS2});
        expect(result.valid).toBe('success');
    });
}, 10000);
