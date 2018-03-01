const AWS = require('aws-sdk');
const rule = require('./iam_avoid_use_of_root_account.livecheck');

let csv =
`user,password_last_used
<root_account>,${(new Date(new Date() - 1000 * 60 * 60 * 24 * 2)).toDateString()}`;

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

describe("IAM_AVOID_USE_OF_ROOT_ACCOUNT", () => {

    test("It recognizes when the root account logged in recently", async () => {
        let result = await rule.validate({provider: _AWS}, 5);
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('Requires <root_account> to not have logged in during the past 5 days. <root_account> logged in 2.46 days ago.')
    });

    test("It recognizes when the root account has not logged in recently", async () => {
        let result = await rule.validate({provider: _AWS}, 2);
        expect(result.valid).toBe('success');
    });
}, 10000);

