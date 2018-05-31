const AWS = require('aws-sdk');
const AWSMock = require('../../../../aws-promise-mock');
let rule = require('./aws-config-service-is-enabled-in-current-region');

describe("aws-config-service-is-enabled", () => {

    let provider1 = new AWSMock();
    provider1.Service("ConfigService", "describeConfigurationRecorderStatus", {ConfigurationRecordersStatus:{recording:false}});

    let provider2 = new AWSMock();
    provider2.Service("ConfigService", "describeConfigurationRecorderStatus",{});

    it("Will fail if services is not configured properly",async () => {
        const result = await rule.livecheck({config: true, provider: provider1});
        expect(result.valid).toBe('fail');
    });

     it("Will succeed if service is enabled", async () => {
         const result = await rule.livecheck({config: true, provider: provider2});
         expect(result.valid).toBe('success');
     });
});