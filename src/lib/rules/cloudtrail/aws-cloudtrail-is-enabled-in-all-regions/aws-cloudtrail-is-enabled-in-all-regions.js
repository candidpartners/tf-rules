// @flow
const {Resource,RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudTrailIsEnabledInAllRegions = {};

CloudTrailIsEnabledInAllRegions.uuid = "a9df5679-8818-457b-baa6-783c62262f2f";
CloudTrailIsEnabledInAllRegions.groupName = "CloudTrail";
CloudTrailIsEnabledInAllRegions.tags = [["CIS", "1.1.0", "2.1"], ["NIST", "SP", "800-171"]];
CloudTrailIsEnabledInAllRegions.config_triggers = ["AWS::CloudTrail::Trail"];
CloudTrailIsEnabledInAllRegions.paths = {CloudTrailIsEnabledInAllRegions: "aws_cloudtrail"};
CloudTrailIsEnabledInAllRegions.docs = {description: 'At least one CloudTrail resource is enabled in all regions.', recommended: true};
CloudTrailIsEnabledInAllRegions.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: "Enabled",
            default: true
        }
    }
};


CloudTrailIsEnabledInAllRegions.livecheck = async function (context /*: Context */) /*: Promise<RuleResult>*/{
    let {config, provider} = context;
    let cloud = new provider.CloudTrail();

    let trails = await cloud.describeTrails().promise();
    let multi = trails.trailList.find(x => x.IsMultiRegionTrail === true);

    return new RuleResult({
       valid: multi ? "success" : "fail",
       message: CloudTrailIsEnabledInAllRegions.docs.description,
       resources: trails.trailList.map(trail => {
           return new Resource({
               is_compliant: trail.IsMultiRegionTrail === true ? true : false,
               resource_id: multi.Name,
               resource_type: "AWS::CloudTrail::Trail",
               message: trail.IsMultiRegionTrail === true ? `has IsMultiRegionTrail enabled.` : `does not have IsMultiRegionTrail enabled.`
           })
       })
    });
};

module.exports = CloudTrailIsEnabledInAllRegions;