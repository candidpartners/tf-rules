'use strict';
const AWS = require('aws-stub');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const _ = require('lodash');
const RealAWS = require('aws-sdk');
const rule = require('./aws-vpc-no-default-vpc');
const co = require('co');

describe('no-vpc', function () {
    it("should return a valid = 'success'", co.wrap(function* () {
        const instance = {AccountAttributes: []};
        const provider = AWS('ec2', 'MyEC2');
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("should return a valid = 'fail'", co.wrap(function* () {
        const instance = {
            AccountAttributes: [
                {
                    AttributeName: "vpc",
                    AttributeValues: [
                        {
                            AttributeValue: "vpc-c385cba4"
                        }
                    ]
                }
            ]
        };
        const provider = AWS('ec2', 'MyOtherEC2');
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));

    it("Recognizes a livecheck", async () => {

        let goodInstance = {
            "AccountAttributes": []
        };

        let badInstance = {
            "AccountAttributes": [
                {
                    "AttributeName": "default-vpc",
                    "AttributeValues": [
                        {
                            "AttributeValue": "vpc-c385cba4"
                        }
                    ]
                }
            ]
        };

        let GoodAWSMock = new AWSPromiseMock();
        GoodAWSMock.Service('EC2', 'describeAccountAttributes', goodInstance);

        let BadAWSMock = new AWSPromiseMock();
        BadAWSMock.Service('EC2', 'describeAccountAttributes', badInstance);

        let result = await rule.livecheck({config: {}, provider: GoodAWSMock});
        expect(result.valid).toBe("success");

        let failResult = await rule.livecheck({config: {}, provider: BadAWSMock});
        expect(failResult.valid).toBe('fail');
        expect(failResult.message).toBe("A default VPC exists.");
    });
});