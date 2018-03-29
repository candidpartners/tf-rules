const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-ensure-access-keys-are-rotated');

let csv = `user,access_key_1_active,access_key_1_last_used_date,access_key_1_last_rotated,access_key_2_active,access_key_2_last_used_date,access_key_2_last_rotated
tes3.user,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 88)).toDateString()},${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()},,false,N/A,N/A
tes4.user,false,N/A,N/A,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 88)).toDateString()},${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()}`;

let _AWS = new AWSPromiseMock();
let content = {
    "Content": csv,
    "GeneratedTime": "2018-03-01T15:28:51Z",
    "ReportFormat": "text/csv"
};

_AWS.Service("IAM", "generateCredentialReport", {"State": "COMPLETE"});
_AWS.Service("IAM", "getCredentialReport", content);

describe("IAM_ENSURE_ACCESS_KEYS_ARE_ROTATED", () => {

    test("It recognizes when the keys are rotated recently enough", async () => {
        let result = await rule.livecheck({provider: _AWS}, 90);
        expect(result.valid).toBe('success');
    });

    test("It recognizes when the keys are not rotated recently enough", async () => {
        let result = await rule.livecheck({provider: _AWS}, 80);
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('2 users have an access key that has not been rotated in 80 days, or not used since it was rotated.');
    });

}, 10000);