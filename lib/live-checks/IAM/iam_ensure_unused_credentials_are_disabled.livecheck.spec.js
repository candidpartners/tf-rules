const AWS = require('aws-sdk');
const rule = require('./iam_ensure_unused_credentials_are_disabled.livecheck');

let csv = `user,password_enabled,password_last_used,access_key_1_active,access_key_1_last_used_date,access_key_2_active,access_key_2_last_used_date
test.user,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 2)).toDateString()},false,N/A,false,N/A
tes2.user,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()},false,N/A,false,N/A
tes3.user,false,N/A,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()},false,N/A
tes4.user,false,N/A,false,N/A,true,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 89)).toDateString()}`;

const _AWS = {
    IAM: class IAM {
        generateCredentialReport() {
            return {
                promise: () => {
                    return Promise.resolve({
                        "State": "COMPLETE"
                    })
                }
            }
        }

        getCredentialReport() {
            return {
                promise: () => {
                    return Promise.resolve({
                            "Content": csv,
                            "GeneratedTime": "2018-03-01T15:28:51Z",
                            "ReportFormat": "text/csv"
                        }
                    )
                }
            }
        }
    }
}

describe("IAM_ENSURE_UNUSED_CREDENTIALS_ARE_DISABLED", () => {

    test("It recognizes when unused credentials have been disabled", async () => {
        let result = await rule.validate({provider: _AWS}, 90);
        expect(result.valid).toBe('success');
    });

    test("It recognizes when unused credentials have not been disabled", async () => {
        let result = await rule.validate({provider: _AWS},88);
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("1 users have a password they have not used in 88 days. 2 users have an access key they have not used in 88 days.");
    });

}, 10000);
