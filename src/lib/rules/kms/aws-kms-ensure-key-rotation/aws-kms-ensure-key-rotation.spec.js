let rule = require('./aws-kms-ensure-key-rotation');

let instance = {
    deletion_window_in_days: 10,
    description: 'KMS key 1',
    enable_key_rotation: true,
    is_enabled: true
};

describe("aws-kms-ensure-key-rotation", () => {
    it("Recognizes an instance with key rotation enabled", function () {
        const context = {config: true, instance};
        const result = rule.validate(context);
        expect(result.valid).toBe('success');
    });

    it("Fails an instance with key rotation enabled", function () {
        let sadInstance = Object.assign({},instance);
        delete sadInstance.enable_key_rotation;

        const context = {config: true, instance: sadInstance};
        const result = rule.validate(context);
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('KMS key rotation needs to be enabled.');
    });

    it("It recognizes being disabled", function () {
        let sadInstance = Object.assign({},instance);
        delete sadInstance.enable_key_rotation;

        const context = {config: false, instance: sadInstance};
        const result = rule.validate(context);
        expect(result.valid).toBe('success');
    });
});

