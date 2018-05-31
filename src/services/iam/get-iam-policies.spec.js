const AWS = require('aws-sdk');
let GetIAMPolicies = require('./get-iam-policies');

jest.setTimeout(10000);
describe("service-get-iam-policies", () => {
    it("Can list all IAM policies", async () => {
        let result = await GetIAMPolicies({provider: AWS, additionalParams: {Scope: "Local"}});
        expect(result.length).toBeGreaterThan(0);
    })
});