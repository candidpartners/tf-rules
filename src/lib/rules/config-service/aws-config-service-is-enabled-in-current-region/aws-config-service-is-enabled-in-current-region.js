// @flow
const debug = require('debug')('snitch/tag-format');
const {Resource, RuleResult, Context} = require('../../../rule-result');
const IsEmpty=require('lodash/isEmpty');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const ConfigServiceEnabled = {};

ConfigServiceEnabled.uuid = "ec28dd0f-59d6-44dd-a87d-f47624cea693";
ConfigServiceEnabled.groupName = "ConfigService";
ConfigServiceEnabled.tags = [["CIS", "1.1.0", "2.5"]];
ConfigServiceEnabled.config_triggers = ["AWS::ConfigService::Enabled"];
ConfigServiceEnabled.paths = {ConfigServiceEnabled: 'aws_config_service'};
ConfigServiceEnabled.docs = {
    description: " Ensure AWS Config is enabled in current region",
    recommended: false
};
ConfigServiceEnabled.schema = {
    type: 'object',
    properties: {}
};
ConfigServiceEnabled.validateS3BucketExists=async (context) => {
    let {config, provider} = context;
    const Cloud = new provider.ConfigService();
    let IsValid=false;
    let result=await Cloud.describeDeliveryChannels().promise();
    if(result && result.DeliveryChannels && result.DeliveryChannels.length > 0) {
        IsValid= !IsEmpty(result.DeliveryChannels[0].s3BucketName)
    }
    return IsValid;

};
ConfigServiceEnabled.validateIfRoleExists= async (context) => {
    let {config, provider} = context;
    const Cloud = new provider.ConfigService();
    let IsValid=false;
    let result=await Cloud.describeConfigurationRecorders().promise();
    if(result && result.ConfigurationRecorders && result.ConfigurationRecorders.length > 0)
        IsValid=!IsEmpty(result.ConfigurationRecorders[0].roleARN);

    return IsValid;
}
ConfigServiceEnabled.livecheck = async (context) => {
    let {config, provider} = context;
    let message="AWS configuration is invalid or not configured for this region";
        const Cloud = new provider.ConfigService();
        let IsValid=false;
        let result=await Cloud.describeConfigurationRecorderStatus().promise();
         if(result && result.ConfigurationRecordersStatus && result.ConfigurationRecordersStatus.length > 0)
             IsValid= result.ConfigurationRecordersStatus[0].recording && ConfigServiceEnabled.validateS3BucketExists(context) && ConfigServiceEnabled.validateIfRoleExists(context);

        return new RuleResult({
            valid: IsValid ? 'success' : 'fail',
            message: IsValid ? '' : message,
            resources: [new Resource({
                is_compliant: IsValid ? true : false,
                resource_id: "ConfigService",
                resource_type: "AWS::ConfigService::Enabled",
                message: IsValid ? `is enabled in this region.` : "is not enabled in this region."
            })]
            // resources: [{
            //         is_compliant: IsValid ? true : false,
            //         resource_id: '',
            //         resource_type: "AWS::Config::Service",
            //         message: IsValid ? '' : message
            //     }]
        })


};

module.exports = ConfigServiceEnabled;

