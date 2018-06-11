// @flow
const debug = require('debug')('snitch/tag-format');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudtrailLogsAreEncrypted = {};

CloudtrailLogsAreEncrypted.uuid = "686cbf59-c41a-4b7f-ae4a-7f50bf91d354";
CloudtrailLogsAreEncrypted.groupName = "CloudTrail";
CloudtrailLogsAreEncrypted.tags = [["CIS", "1.1.0", "2.7"]];
CloudtrailLogsAreEncrypted.config_triggers = ["AWS::CloudTrail::Trail"];
CloudtrailLogsAreEncrypted.paths = {CloudtrailLogsAreEncrypted: 'aws_cloudtrail'};
CloudtrailLogsAreEncrypted.docs = {
    description: "All CloudTrail logs are encrypted at rest.",
    recommended: false
};
CloudtrailLogsAreEncrypted.schema = {
    type: 'object',
    properties: {}
};


CloudtrailLogsAreEncrypted.livecheck = async function (context /*: Context*/) /*: Promise<RuleResult> */ {
    let {config, provider} = context;

    let Cloud = new provider.CloudTrail();
    let trail = await Cloud.describeTrails().promise();
    let trails = trail.trailList;
    let UnencryptedTrails = trails.filter(x => !x.hasOwnProperty("KmsKeyId"));

    return new RuleResult({
        valid: (UnencryptedTrails.length > 0) ? "fail" : "success",
        message: CloudtrailLogsAreEncrypted.docs.description,
        resources: trails.map(t => {
            let isUnencrypted = !t.hasOwnProperty("KmsKeyId");
            return new Resource({
                is_compliant: isUnencrypted ? false : true,
                resource_id: t.Name,
                resource_type: "AWS::CloudTrail::Trail",
                message: isUnencrypted ? "is not encrypted.": "is encrypted."
            })
        })
    })
};

module.exports = CloudtrailLogsAreEncrypted;

