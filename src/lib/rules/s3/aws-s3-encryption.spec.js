'use strict';
const AWS = require('aws-stub');
const AWSPromiseMock = require('../../../aws-promise-mock');
const _ = require('lodash');
const RealAWS = require('aws-sdk');
const rule = require('./aws-s3-encryption');
const co = require('co');

describe('s3-encryption', function () {
    it("should return a valid = 'success'", co.wrap(function* () {
        const instance = {
            "server_side_encryption_configuration": [
                {
                    "rule": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }
                    ]
                }
            ]
        };
        const provider = AWS('S3', 'MyS3Bucket');
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("should return a valid = 'fail'", co.wrap(function* () {
        const instance = {};
        const provider = AWS('S3', 'MyOtherS3Bucket');
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));

    it("Recognizes a livecheck", async () => {

        let goodBuckets = {
            "Owner": {
                "DisplayName": "aws-volker-nonprod",
                "ID": "65405b1349bffb683d88038bcf3250d5072b44fba3f8b3cee88d1166f980e01a"
            },
            "Buckets": [
                {
                    "CreationDate": "2017-07-04T02:02:34.000Z",
                    "Name": "bucket-1"
                },
                {
                    "CreationDate": "2018-02-02T02:19:59.000Z",
                    "Name": "bucket-2"
                }
            ]
        };
        let goodBucket = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        };

        let badBuckets = {
            "Owner": {
                "DisplayName": "aws-volker-nonprod",
                "ID": "65405b1349bffb683d88038bcf3250d5072b44fba3f8b3cee88d1166f980e01a"
            },
            "Buckets": [
                {
                    "CreationDate": "2017-07-04T02:02:34.000Z",
                    "Name": "bucket-3"
                },
                {
                    "CreationDate": "2018-02-02T02:19:59.000Z",
                    "Name": "bucket-4"
                },
            ]
        };

        let GoodAWSMock = new AWSPromiseMock();
        GoodAWSMock.Service('S3', 'listBuckets', goodBuckets);
        GoodAWSMock.Service('S3', 'getBucketEncryption', goodBucket);

        let BadAWSMock = new AWSPromiseMock();
        BadAWSMock.Service('S3', 'listBuckets', badBuckets);
        BadAWSMock.ServiceError('S3', 'getBucketEncryption', {code: "ServerSideEncryptionConfigurationNotFoundError"});

        let result = await rule.livecheck({config: {}, provider: GoodAWSMock});
        expect(result.valid).toBe("success");

        let failResult = await rule.livecheck({config: {}, provider: BadAWSMock});
        expect(failResult.valid).toBe('fail');
        expect(failResult.message).toBe("One or more S3 buckets are not encrypted.");
    });

    it("It can exclude instances", async () => {
        let goodBuckets = {
            "Buckets": [
                {
                    "CreationDate": "2017-07-04T02:02:34.000Z",
                    "Name": "bucket-1"
                },
                {
                    "CreationDate": "2018-02-02T02:19:59.000Z",
                    "Name": "bucket-2"
                }
            ]
        };
        let goodBucket = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        };

        let GoodAWSMock = new AWSPromiseMock();
        GoodAWSMock.Service('S3', 'listBuckets', goodBuckets);
        GoodAWSMock.Service('S3', 'getBucketEncryption', goodBucket);

        let result = await rule.livecheck({config: {exclude: "bucket-2"}, provider: GoodAWSMock});
        expect(result.valid).toBe("success");
    })
});