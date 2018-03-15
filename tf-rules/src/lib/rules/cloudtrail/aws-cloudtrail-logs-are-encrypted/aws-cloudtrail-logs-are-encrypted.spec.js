let rule = require('./aws-cloudtrail-logs-are-encrypted');

let instance = {kms_key_id: "my_key_arn"};

describe("aws-cloudtrail-logs-are-encrypted", () => {
    it("Will fail if logs are not encrypted", () => {
        const context = {config: true, instance};
        const result = rule.validate(context);
        expect(result.valid).toBe('success');
    });

    it("Will succeed if logs are encrypted", () => {
        const context = {config: true, instance: {}};
        const result = rule.validate(context);
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('Cloudtrail logs must be encrypted. Please set a kms_key_id');
    });

    it("Will succeed if config is set to false", () => {
        const context = {config: false, instance: {}};
        const result = rule.validate(context);
        expect(result.valid).toBe('success');
    });
});