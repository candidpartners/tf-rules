const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-ensure-unused-credentials-are-disabled');

let csv = `user,password_enabled,password_last_used,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date
test.user,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 2)).toDateString()},false,N/A,false,N/A
tes2.user,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()},false,N/A,false,N/A
tes3.user,false,N/A,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()},false,N/A
tes4.user,false,N/A,false,N/A,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()}`;

let _AWS = new AWSPromiseMock();
let MockService = { IAM: {
        GetIAMCredentialReport: () => Promise.resolve(csv)
    }
};
describe("IAM_ENSURE_UNUSED_CREDENTIALS_ARE_DISABLED", () => {

    test("It recognizes when unused credentials have been disabled", async () => {
        let result = await rule.livecheck({config: {days: 90}, provider: _AWS,services:MockService});
        expect(result.valid).toBe('success');
    });

    test("It recognizes when unused credentials have not been disabled", async () => {
        let result = await rule.livecheck({config: {days: 88}, provider: _AWS,services:MockService});
        expect(result.valid).toBe('fail');
        expect(result.message).toBeTruthy();
    });

}, 10000);
