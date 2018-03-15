const AWS = require('aws-stub');
const rule = require('./aws-iam-user-policy-does-not-exist');
const debug = require('debug')('snitch/aws-security-group-does-not-allow-outbound.spec');

let provider = {};

let instance = {};

describe('aws-iam-user-policy-does-not-exist conforms to CIS', function () {

    it("Will fail if it recognizes a IAM User Policy Attachment", function () {
        const context = {config: {},instance, provider};
        const result = rule.validate(context);
        expect(result.valid).toBe('fail');
    });
});