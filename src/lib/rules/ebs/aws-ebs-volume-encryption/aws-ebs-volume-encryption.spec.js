'use strict';
const AWS = require('aws-stub');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const _ = require('lodash');
const RealAWS = require('aws-sdk');
const rule = require('./aws-ebs-volume-encryption');
const co = require('co');

describe('ebs-encryption', function () {
    it("should return a valid = 'success'", co.wrap(function* () {
        const instance = {VolumeId: 'MyEBSVolume', encrypted: true};
        const provider = AWS('EC2', 'MyEC2Instance');
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("should return a valid = 'fail'", co.wrap(function* () {
        const instance = {VolumeId: 'MyOtherEBSVolume', encrypted: false};
        const provider = AWS('EC2', 'MyOtherEC2Instance');
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));

    it("Recognizes a livecheck", async () => {
        let goodVolumes = {
            Volumes: [
                {
                    "Encrypted": true
                },
                {
                    "Encrypted": true
                }
            ]
        };
        let badVolumes = {
            Volumes: [
                {
                    "Encrypted": false
                },
                {
                    "Encrypted": false
                }
            ]
        };

        let GoodAWSMock = new AWSPromiseMock();
        GoodAWSMock.Service('EC2', 'describeVolumes', goodVolumes);

        let BadAWSMock = new AWSPromiseMock();
        BadAWSMock.Service('EC2', 'describeVolumes', badVolumes);

        let result = await rule.livecheck({config: {}, provider: GoodAWSMock});
        expect(result.valid).toBe("success");

        let failResult = await rule.livecheck({config: {}, provider: BadAWSMock});
        expect(failResult.valid).toBe('fail');
        expect(failResult.message).toBeTruthy();
    });

    it("It can exclude instances", async () => {
        let volumes = {
            Volumes: [
                {
                    "VolumeId": "goodVolume",
                    "Encrypted": true
                },
                {
                    "VolumeId": "badVolume",
                    "Encrypted": false
                }
            ]
        };

        let GoodAWSMock = new AWSPromiseMock();
        GoodAWSMock.Service('EC2', 'describeVolumes', volumes);

        let result = await rule.livecheck({config: {exclude: ["badVolume"]}, provider: GoodAWSMock});
        expect(result.valid).toBe("success");
    })
});