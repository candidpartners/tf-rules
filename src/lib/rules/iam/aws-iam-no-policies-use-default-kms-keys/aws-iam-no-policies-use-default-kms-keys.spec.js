// const AWS = require('aws-sdk');
// const services = require('../../../services/services');
const AWSMock = require('../../../../aws-promise-mock');
const rule = require('./aws-iam-no-policies-use-default-kms-keys');

describe('aws-iam-no-policies-use-default-kms-keys', () => {
    it("Can check if a policy uses a default key", async () => {
        let provider = new AWSMock();
        provider.Service("KMS", "listAliases", {
                Aliases:
                    [
                        {
                            AliasName: 'alias/Volker-dev-key',
                            AliasArn: 'arn:aws:kms:us-west-2:421471939647:alias/Volker-dev-key',
                            TargetKeyId: '17cf0141-92cb-408b-8def-75ed616135f7'
                        },
                        {
                            AliasName: 'alias/aws/lambda',
                            AliasArn: 'arn:aws:kms:us-west-2:421471939647:alias/aws/lambda',
                            TargetKeyId: '13416b34-41f0-45c7-a6b7-28b973de6624'
                        },
                    ],
                Truncated: false
            }
        );

        let MockService = { IAM: {
                GetIAMPolicies: () => Promise.resolve([
                    {
                        "Policy": {
                            "PolicyName": "uses-default-lambda-key",
                            "PolicyId": "ANPAI5EAVZ7HVGVD2USTO",
                            "Arn": "arn:aws:iam::421471939647:policy/uses-default-lambda-key",
                            "Path": "/",
                            "DefaultVersionId": "v1",
                            "AttachmentCount": 0,
                            "IsAttachable": true,
                            "CreateDate": "2018-04-18T16:22:41.000Z",
                            "UpdateDate": "2018-04-18T16:22:41.000Z"
                        },
                        "PolicyVersion": {
                            "Document": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "VisualEditor0",
                                        "Effect": "Allow",
                                        "Action": [
                                            "kms:ListKeys",
                                            "kms:GenerateRandom",
                                            "kms:ListAliases",
                                            "kms:GenerateDataKey",
                                            "kms:ReEncryptTo",
                                            "kms:CreateKey",
                                            "kms:ReEncryptFrom"
                                        ],
                                        "Resource": "*"
                                    },
                                    {
                                        "Sid": "VisualEditor1",
                                        "Effect": "Allow",
                                        "Action": "kms:*",
                                        "Resource": "arn:aws:kms:*:*:alias/aws/lambda"
                                    }
                                ]
                            },
                            "VersionId": "v1",
                            "IsDefaultVersion": true,
                            "CreateDate": "2018-04-18T16:22:41.000Z"
                        }
                    },
                    {
                        "Policy": {
                            "PolicyName": "Volker-Automated-Test-Role",
                            "PolicyId": "ANPAJ5WZU7SHVZCEB6C7M",
                            "Arn": "arn:aws:iam::421471939647:policy/Volker-Automated-Test-Role",
                            "Path": "/",
                            "DefaultVersionId": "v1",
                            "AttachmentCount": 1,
                            "IsAttachable": true,
                            "CreateDate": "2017-12-21T14:46:28.000Z",
                            "UpdateDate": "2017-12-21T14:46:28.000Z"
                        },
                        "PolicyVersion": {
                            "Document": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "",
                                        "Effect": "Allow",
                                        "Action": "execute-api:Invoke",
                                        "Resource": "arn:aws:execute-api:*:*:k8fxfk3581/*"
                                    }
                                ]
                            },
                            "VersionId": "v1",
                            "IsDefaultVersion": true,
                            "CreateDate": "2017-12-21T14:46:28.000Z"
                        }
                    },
                    {
                        "Policy": {
                            "PolicyName": "Volker_UI_Lambda_Role",
                            "PolicyId": "ANPAIC2L2ASF6LHMNIT3Q",
                            "Arn": "arn:aws:iam::421471939647:policy/Volker_UI_Lambda_Role",
                            "Path": "/",
                            "DefaultVersionId": "v4",
                            "AttachmentCount": 1,
                            "IsAttachable": true,
                            "CreateDate": "2017-10-16T16:04:43.000Z",
                            "UpdateDate": "2017-10-20T14:01:57.000Z"
                        },
                        "PolicyVersion": {
                            "Document": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "lambda:InvokeFunction"
                                        ],
                                        "Resource": [
                                            "arn:aws:lambda:us-west-2:421471939647:function:factory2_qa",
                                            "arn:aws:lambda:us-west-2:421471939647:function:factory2_prod"
                                        ]
                                    }
                                ]
                            },
                            "VersionId": "v4",
                            "IsDefaultVersion": true,
                            "CreateDate": "2017-10-20T14:01:57.000Z"
                        }
                    }
                ])
            }};

        let result = await rule.livecheck({provider: provider, services: MockService});
        expect(result.valid).toBe('fail');
        expect(result.resources.filter(x => x.is_compliant)).toHaveLength(2);
        expect(result.resources.filter(x => !x.is_compliant)).toHaveLength(1);
    })
});
