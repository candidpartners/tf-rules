const AWS = require('aws-sdk');
let GetIAMCredentialReport = require('./get-iam-credential-report-services');

jest.setTimeout(10000);
describe("service-get-iam-credential-report-services", () => {
    it("Can generate IAM credential report", async () => {
        let result = await GetIAMCredentialReport({provider: AWS});
        expect(result.length).toBeGreaterThan(0);
    })
});