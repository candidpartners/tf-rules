const AWS = require('aws-sdk');
const AWSMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-mfa-is-enabled-for-root-account');

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

        let result = await rule.livecheck({provider: provider});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('Root account does not have MFA enabled.');
    });

    test("Can confirm if valid = success", async () => {

        let provider = new AWSMock();
        provider.Service("IAM","generateCredentialReport",{});
        provider.Service("IAM","getCredentialReport", {
            Content: csv2
        });

        let result = await rule.livecheck({provider: provider});
        expect(result.valid).toBe('success');
    })
});