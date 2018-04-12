'use strict';
const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-ec2-ensure-instance-profile');
const co = require('co');

describe('aws-ec2-ensure-instance-profile', function() {
    it("Should recognize valid instances", async () => {
        let provider = new AWSPromiseMock();
        provider.Service("EC2","describeInstances",{
            Reservations: [
                {
                    Instances: [
                        {
                            InstanceId: "foo",
                            IamInstanceProfile: {
                                Arn: "MyARN"
                            }
                        },
                        {
                            InstanceId: "bar"
                        }
                    ]
                }
            ]
        });
        let result = await rule.livecheck({provider: provider});
        expect(result.valid).toBe('fail');
        expect(result.resources[0].is_compliant).toBeTruthy();
        expect(result.resources[1].is_compliant).toBeFalsy();
    });

    it("tf-check", () => {
        let result = rule.validate({ instance: {iam_instance_profile: "MyARN"}})
        expect(result.valid).toBe('success');
        let result2 = rule.validate({instance: {}});
        expect(result2.valid).toBe('fail');
    })
});

