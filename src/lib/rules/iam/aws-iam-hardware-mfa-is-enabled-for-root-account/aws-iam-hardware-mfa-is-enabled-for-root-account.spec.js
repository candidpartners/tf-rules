const AWS = require('aws-sdk');
const AWSMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-hardware-mfa-is-enabled-for-root-account');

let csv =
    `user,arn,password_enabled,mfa_active
<root_account>,my_arn,true,false`;

let csv2 =
    `user,arn,password_enabled,mfa_active
<root_account>,my_arn,true,true`;

describe("mfa-is-enabled-for-root-account", () => {
    test("Can confirm if valid = fail", async () => {

        let provider = new AWSMock();
        provider.Service("IAM","generateCredentialReport",{});
        provider.Service("IAM","getCredentialReport", {
            Content: csv
        });
        provider.Service("IAM","listMFADevices", {});

        let result = await rule.livecheck({provider: provider});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('Root account does not have hardware MFA enabled.');
    });

    test("Can confirm if valid = success", async () => {

        let provider = new AWSMock();
        provider.Service("IAM","generateCredentialReport",{});
        provider.Service("IAM","getCredentialReport", {
            Content: csv2
        });
        provider.Service("IAM","listMFADevices", {
            "MFADevices": [
                {
                    "UserName": "<root_account>",
                    "SerialNumber": "arn:aws:iam::123456789012:mfa/BobsMFADevice",
                    "EnableDate": "2015-06-16T22:36:37Z"
                }
            ]
        });

        let result = await rule.livecheck({provider: provider});
        expect(result.valid).toBe('success');
    })
});