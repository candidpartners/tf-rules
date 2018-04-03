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
    test("It fails becuase a no MFA device exists on the account.", async () => {

        let provider = new AWSMock();
        provider.Service("IAM", "generateCredentialReport", {});
        provider.Service("IAM", "getCredentialReport", {Content: csv});
        provider.Service("IAM", "listVirtualMFADevices", {});

        let result = await rule.livecheck({provider: provider});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('Root account does not have hardware MFA enabled.');
    });

    test("It fails becuase a virtual MFA device exists on the root account.", async () => {

        let provider = new AWSMock();
        provider.Service("IAM", "generateCredentialReport", {});
        provider.Service("IAM", "getCredentialReport", {
            Content: csv
        });
        provider.Service("IAM", "listVirtualMFADevices", {
            "VirtualMFADevices": [
                {
                    SerialNumber: 'arn:aws:iam::421471939647:mfa/root-account-mfa-device',
                    User:
                        {
                            UserName: 'candid-volker',
                            UserId: '421471939647',
                            Arn: 'arn:aws:iam::421471939647:root'
                        }
                }
            ]
        });

        let result = await rule.livecheck({provider: provider});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('Root account does not have hardware MFA enabled.');
    });

    test("Can confirm if valid = success", async () => {

        let provider = new AWSMock();
        provider.Service("IAM", "generateCredentialReport", {});
        provider.Service("IAM", "getCredentialReport", {Content: csv2});
        provider.Service("IAM", "listVirtualMFADevices", {});

        let result = await rule.livecheck({provider: provider});
        expect(result.valid).toBe('success');
    })
});