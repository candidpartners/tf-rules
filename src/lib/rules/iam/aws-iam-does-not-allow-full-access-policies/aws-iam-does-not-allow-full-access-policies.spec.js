const AWS = require('aws-stub');
const rule = require('./aws-iam-does-not-allow-full-access-policies');
const debug = require('debug')('tfrules/aws-security-group-does-not-allow-outbound.spec');

let provider = {};

let GoodPolicy = {
    description: 'My test policy',
    name: 'test_policy',
    path: '/',
    policy: '{\\n  \\"Version\\": \\"2012-10-17\\",\\n  \\"Statement\\": [\\n    {\\n      \\"Action\\": [\\n        \\"s3:ListAllMyBuckets\\"\\n      ],\\n      \\"Effect\\": \\"Allow\\",\\n      \\"Resource\\": \\"*\\"\\n    }\\n  ]\\n}\\n'
};

let BadPolicy = { description: 'My test policy',
    name: 'test_policy',
    path: '/',
    policy: '{\\n  \\"Version\\": \\"2012-10-17\\",\\n  \\"Statement\\": [\\n    {\\n      \\"Action\\": [\\n        \\"*\\"\\n      ],\\n      \\"Effect\\": \\"Allow\\",\\n      \\"Resource\\": \\"*\\"\\n    }\\n  ]\\n}\\n' };

describe('aws-iam-user-policy-does-not-exist conforms to CIS', function () {

    it("Will fail if it recognizes an IAM policy with *:*", function () {
        const context = {config: {}, instance:BadPolicy, provider};
        const result = rule.validate(context);
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('CIS 1.24 - IAM Policies must not allow Action: * on Resource: *. Please check policy test_policy');
    });

    it("Will succeed if no IAM policy has *:*", function () {
        const context = {config: {}, instance: GoodPolicy, provider};
        const result = rule.validate(context);
        expect(result.valid).toBe('success');
    })
});