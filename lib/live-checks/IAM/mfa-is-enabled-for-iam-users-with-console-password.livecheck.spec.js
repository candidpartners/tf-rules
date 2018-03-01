const AWS = require('aws-sdk');
const rule = require('./mfa-is-enabled-for-iam-users-with-console-password.livecheck');

const _AWS = {
    IAM: class IAM {
        listUsers() {
            return {
                promise() {
                    return Promise.resolve({
                        Users: [
                            {
                                Path: '/',
                                UserName: 'Test.User',
                                UserId: 'MY_ID',
                                Arn: 'arn:aws:iam::421471939647:user/Test.User',
                                CreateDate: "2017-10-31T15:18:20.000Z",
                                PasswordLastUsed: "2018-02-09T18:07:05.000Z"
                            },
                            {
                                Path: '/',
                                UserName: 'No.MFA',
                                UserId: 'MY_ID',
                                Arn: 'arn:aws:iam::421471939647:user/Test.User',
                                CreateDate: "2017-10-31T15:18:20.000Z",
                                PasswordLastUsed: "2018-02-09T18:07:05.000Z"
                            }
                        ]
                    })
                }
            }
        }

        listMFADevices({UserName}) {
            return {
                promise() {
                    if (UserName == "No.MFA")
                        return Promise.resolve({
                            MFADevices: []
                        });
                    else
                        return Promise.resolve({
                            "MFADevices": [
                                {
                                    "UserName": UserName,
                                    "SerialNumber": "arn:aws:iam::123456789012:mfa/BobsMFADevice",
                                    "EnableDate": "2015-06-16T22:36:37Z"
                                }
                            ]
                        })
                }
            }
        }
    }
}

describe("mfa-is-enabled-for-iam-users-with-console-password", () => {
    test("Can confirm if valid", async () => {
        let result = await rule.validate({provider: _AWS});
        expect(result.valid).toBe('fail');
        expect(result.message.includes("1")).toBeTruthy();
    })
});
