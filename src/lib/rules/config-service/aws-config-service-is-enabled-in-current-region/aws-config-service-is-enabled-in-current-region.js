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
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: false
        }
    }
};


ConfigServiceEnabled.livecheck = async (context) => {
    let {config, provider} = context;
    let message="AWS configuration is not valid";
    try {
        const Cloud = new provider.ConfigService();
        let result=await Cloud.describeConfigurationRecorderStatus().promise();
        if(result && result.ConfigurationRecordersStatus && result.ConfigurationRecordersStatus.length >= 0)
        {
            const configurationRecordersStatus=result.ConfigurationRecordersStatus[0];
            if(configurationRecordersStatus.recording)
            {
                result=await Cloud.describeDeliveryChannels().promise();
                if(result && result.DeliveryChannels && result.DeliveryChannels.length >= 0)
                {
                    if(IsEmpty(result.DeliveryChannels[0].s3BucketName)) {
                        message = "AWS configuration must have s3 bucket defined";
                    }
                    else {
                        result=await Cloud.describeConfigurationRecorders().promise()
                        if(result && result.ConfigurationRecorders && result.ConfigurationRecorders.length >= 0)
                        {
                            if(IsEmpty(result.ConfigurationRecorders[0].roleARN))
                                message="AWS configuration must have a role defined";
                            else {
                                result={};
                                message="";
                            }
                        }
                    }
                }
                else
                {
                    message="AWS configuration is not valid"
                }
            }
            else
            {
                message="AWS configuration is missing or should be enabled"
            }
        }
        return new RuleResult({
            valid: IsEmpty(result) ? 'success' : 'fail',
            message: message,
            resources: result
        })
    }
    catch (e) {
        console.log(e);
        return new RuleResult({
            valid: 'fail',
            message: e.message,
            resources: {}
        })
    }

};

module.exports = ConfigServiceEnabled;

