'use strict';
const AWS = require('aws-stub');
const RealAWS = require('aws-sdk');
const rule = require('./aws-rds-encryption-key-exists');
const co = require('co');

const Keys = [
    'whatever',
    'arn:fake:key:id',
    'something'
].map(KeyArn => ({KeyArn}));

describe('rds-encryption-key-exists', function () {
    it("should return a valid = 'success'", co.wrap(function* () {
        const instance = {kms_key_id: 'arn:fake:key:id'};
        const provider = AWS('KMS', 'listKeys', {Keys});
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("should return a valid = 'fail'", co.wrap(function* () {
        const instance = {kms_key_id: 'arn:fake:key:id:not:exist'};
        const provider = AWS('KMS', 'listKeys', {Keys});
        const context = {config: true, instance, provider};
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));

    it("Recognizes a livecheck", async () => {
        let goodProvider = AWS("RDS", "describeDBInstances",
            {
                DBInstances: [
                    {
                        // Other instance data just omitted
                        kms_key_id: "kms_key"
                    }
                ]
            }
        );
        let badProvider = AWS("RDS", "describeDBInstances",
            {
                DBInstances: [
                    {
                        // Other instance data just omitted
                        kms_key_id: undefined
                    }
                ]
            }
        );

        let result = await rule.livecheck({config: {}, provider: goodProvider});
        expect(result.valid).toBe("success");

        let failResult = await rule.livecheck({config: {}, provider: badProvider});
        expect(failResult.valid).toBe('fail');
        expect(failResult.message).toBe("One or more RDS instances are not encrypted.");
    });

    it("It can exclude instances", async () => {
        let goodProvider = AWS("RDS", "describeDBInstances",
            {
                DBInstances: [
                    {
                        // Other instance data just omitted
                        DBInstanceIdentifier: "MyName",
                        kms_key_id: undefined
                    },
                    {
                        // Other instance data just omitted
                        DBInstanceIdentifier: "Instance 2",
                        kms_key_id: "kms_key"
                    }
                ]
            }
        );
        let result = await rule.livecheck({config: { exclude: "MyName"}, provider: goodProvider});
        expect(result.valid).toBe("success");
    })
});