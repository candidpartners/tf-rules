const AWS = require('aws-stub');
const rule = require('./aws-cloudtrail-ensure-log-file-validation');
const debug = require('debug')('snitch/aws-security-group-does-not-allow-outbound.spec');

let provider = {};

const goodInstance = {
    enable_log_file_validation: true,
    enable_logging: true,
    event_selector: [[Object]],
    include_global_service_events: false,
    is_multi_region_trail: false,
    name: 'tf-trail-foobar',
    s3_bucket_name: 'my-bucket',
    s3_key_prefix: 'prefix'
};

const badInstance = {
    enable_log_file_validation: false,
    enable_logging: true,
    event_selector: [[Object]],
    include_global_service_events: false,
    is_multi_region_trail: false,
    name: 'tf-trail-foobar',
    s3_bucket_name: 'my-bucket',
    s3_key_prefix: 'prefix'
};

describe('aws-cloudtrail-ensure-log-file-validation', function () {

    it("Will fail if log file validation is false", function () {
        const context = {config: {}, instance: badInstance, provider};
        const result = rule.validate(context);
        expect(result.valid).toBe('fail');
        expect(result.message).toBe('Cloudtrail tf-trail-foobar has enable_log_file_validation set to false');
    });

    it("Will succeed if log file validation is true", function () {
        const context = {config: {}, instance: goodInstance, provider};
        const result = rule.validate(context);
        expect(result.valid).toBe('success');
    });
});