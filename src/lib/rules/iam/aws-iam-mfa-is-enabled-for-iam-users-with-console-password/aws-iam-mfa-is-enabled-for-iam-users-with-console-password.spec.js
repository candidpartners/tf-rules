const AWS = require('aws-sdk');
const AWSMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-mfa-is-enabled-for-iam-users-with-console-password');

let csv =
`user,arn,password_enabled,mfa_active
my_user,my_arn,true,false`;

let csv2 =
`user,arn,password_enabled,mfa_active
my_user,my_arn,true,true`;

describe("mfa-is-enabled-for-iam-users-with-console-password", () => {
    test("Can confirm if valid = fail", async () => {

        let provider = new AWSMock();
        provider.Service("IAM","generateCredentialReport",{});
        provider.Service("IAM","getCredentialReport", {
            Content: csv
        });

        let result = await rule.livecheck({provider: provider});
        expect(result.valid).toBe('fail');
        expect(result.noncompliant_resources).toHaveLength(1);
    })

    test("Can confirm if valid = fail", async () => {

        let provider = new AWSMock();
        provider.Service("IAM","generateCredentialReport",{});
        provider.Service("IAM","getCredentialReport", {
            Content: csv2
        });

        let result = await rule.livecheck({provider: provider});
        expect(result.valid).toBe('success');
    })
});
