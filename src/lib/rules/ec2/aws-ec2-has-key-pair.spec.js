'use strict';
const rule = require('./aws-ec2-has-key-pair');
const co = require('co');
const _ = require('lodash');
const debug = require('debug')('snitch/aws-ec2-key-pair-exists');

describe('aws-ec2-key-pair-exists', function () {
    it("should return a valid = 'success'", co.wrap(function* () {
        const instance = {
            key_name: 'real-key-name',
            tags: {
                ApplicationCode: 'TST',
                Name: 'TestInstance'
            }
        };

        const provider = {};
        const context = {
            config: true,
            instance,
            provider
        };
        const result = yield rule.validate(context);
        expect(result.valid).toBe('success');
    }));
    it("should return a valid = 'fail'", co.wrap(function* () {
        const instance = {
            tags: {
                ApplicationCode: 'TST',
                Name: 'TestInstance'
            }
        };

        const provider = {};
        const context = {
            config: true,
            instance,
            provider
        };
        const result = yield rule.validate(context);
        expect(result.valid).toBe('fail');
    }));
});