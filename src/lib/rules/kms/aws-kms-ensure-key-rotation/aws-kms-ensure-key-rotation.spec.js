const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
let rule = require('./aws-kms-ensure-key-rotation');

let instance = {
    deletion_window_in_days: 10,
    description: 'KMS key 1',
    enable_key_rotation: true,
    is_enabled: true
};

describe("aws-kms-ensure-key-rotation", () => {
    it("Recognizes an instance with key rotation enabled", function () {
        const context = {config: {enabled: true}, instance};
        const result = rule.validate(context);
        expect(result.valid).toBe('success');
    });

    it("Fails an instance with key rotation disabled", function () {
        let sadInstance = Object.assign({enable_key_rotation: false},instance);
        delete sadInstance.enable_key_rotation;

        const context = {config: {enabled: true}, instance: sadInstance};
        const result = rule.validate(context);
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('KMS key rotation is not enabled for one or more keys.');
    });

    it("It recognizes being disabled", function () {
        let sadInstance = Object.assign({},instance);
        delete sadInstance.enable_key_rotation;

        const context = {config: {enabled: false}, instance: sadInstance};
        const result = rule.validate(context);
        expect(result.valid).toBe('success');
    });

    it("Passes a live check", async () => {
       let provider = new AWSPromiseMock();
       provider.Service("KMS", "listKeys", {Keys: [{KeyId: "MyId", KeyArn: "MyArn"}]});
       provider.Service("KMS", "getKeyRotationStatus", [{ KeyRotationEnabled: true }]);
       let result = await rule.livecheck({config: {enabled: true}, provider: provider});
       expect(result.valid).toBe("success");
    });
});

