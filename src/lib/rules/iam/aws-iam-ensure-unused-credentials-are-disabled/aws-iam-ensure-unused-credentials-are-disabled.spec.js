const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-ensure-unused-credentials-are-disabled');

let csv = `user,password_enabled,password_last_used,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date
test.user,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 2)).toDateString()},false,N/A,false,N/A
tes2.user,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()},false,N/A,false,N/A
tes3.user,false,N/A,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()},false,N/A
tes4.user,false,N/A,false,N/A,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()}`;

let _AWS = new AWSPromiseMock();
let content = {
    "Content": csv,
    "GeneratedTime": "2018-03-01T15:28:51Z",
    "ReportFormat": "text/csv"
};

_AWS.Service("IAM", "generateCredentialReport", {"State": "COMPLETE"});
_AWS.Service("IAM", "getCredentialReport", content);

describe("IAM_ENSURE_UNUSED_CREDENTIALS_ARE_DISABLED", () => {

    test("It recognizes when unused credentials have been disabled", async () => {
        let result = await rule.livecheck({provider: _AWS}, 90);
        expect(result.valid).toBe('success');
    });

    test("It recognizes when unused credentials have not been disabled", async () => {
        let result = await rule.livecheck({provider: _AWS},88);
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("1 users have a password they have not used in 88 days. 2 users have an access key they have not used in 88 days.");
    });

}, 10000);
