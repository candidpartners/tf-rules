const AWS = require('aws-sdk');
const AWSMock = require('../../../../aws-promise-mock');
let rule = require('./aws-config-service-is-enabled-in-current-region');

describe("aws-config-service-is-enabled", () => {

    let provider1 = new AWSMock();
    provider1.Service("ConfigService", "describeConfigurationRecorderStatus", {ConfigurationRecordersStatus:{recording:false}});

    let provider2 = new AWSMock();
    provider2.Service("ConfigService", "describeConfigurationRecorderStatus",{ConfigurationRecordersStatus:[{recording:true,message:''}]});

    let provider3 = new AWSMock();
    provider3.Service("ConfigService", "describeDeliveryChannels",{ DeliveryChannels:
            [ { name: 'config',
                s3BucketName: 'config.fake-bucket',
                configSnapshotDeliveryProperties: [Object] } ] });

    let provider4 = new AWSMock();
    provider4.Service("ConfigService", "describeConfigurationRecorders",{ ConfigurationRecorders:
            [ { name: 'default',
                roleARN: 'arn:aws:iam::fake:role/config',
                recordingGroup: [Object] } ] });

    it("Will fail if services is not configured properly",async () => {
        const result = await rule.livecheck({config: true, provider: provider1});
        expect(result.valid).toBe('fail');
    });

    it("Will succeed if service is enabled", async () => {
         const result = await rule.livecheck({config: true, provider: provider2});
         expect(result.valid).toBe('success');
    });

    it("Will validate  if service is enabled and S3 bucket is defined", async () => {
        const result = await rule.validateS3BucketExists({config: true, provider: provider3});
        expect(result).toBeTruthy()
    });
    it("Will return false if service is enabled and S3 bucket is not defined", async () => {
        provider3.Service("ConfigService", "describeDeliveryChannels",{});
        const result = await rule.validateS3BucketExists({config: true, provider: provider3});
        expect(result).toBeFalsy()
    });
    it("Will validate  if service is enabled and Role is defined", async () => {
        const result = await rule.validateIfRoleExists({config: true, provider: provider4});
        expect(result).toBeTruthy()
    });
    it("Will return false if service is enabled and Role is not defined", async () => {
        provider4.Service("ConfigService", "describeConfigurationRecorders",{});
        const result = await rule.validateIfRoleExists({config: true, provider: provider4});
        expect(result).toBeFalsy()
    });
});