const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource,RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudTrailIsEnabledInAllRegions = {};

CloudTrailIsEnabledInAllRegions.uuid = "a9df5679-8818-457b-baa6-783c62262f2f";
CloudTrailIsEnabledInAllRegions.groupName = "CloudTrail";
CloudTrailIsEnabledInAllRegions.tags = ["CIS | 1.1.0 | 2.1"];
CloudTrailIsEnabledInAllRegions.config_triggers = ["AWS::CloudTrail::Trail"];
CloudTrailIsEnabledInAllRegions.paths = {CloudTrailIsEnabledInAllRegions: "aws_cloudtrail"};
CloudTrailIsEnabledInAllRegions.docs = {description: 'At least one CloudTrail resource is enabled in all regions.', recommended: true};
CloudTrailIsEnabledInAllRegions.schema = {type: 'boolean'};


CloudTrailIsEnabledInAllRegions.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let cloud = new provider.CloudTrail();

    let trails = yield cloud.describeTrails().promise();
    let multi = trails.trailList.map(x => x.IsMultiRegionTrail);

    if (!multi.includes(true)) {
        return new RuleResult({
            valid: "fail",
            message: "There are no CloudTrail resources that are enabled in all regions.",
            noncompliant_resources: [
                new NonCompliantResource({
                    resource_id: "Cloudtrail",
                    resource_type: "AWS::::Account",
                    message: "There isn't a Cloudtrail that is enabled for all regions."
                })
            ]
        })
    }
    else return new RuleResult({
        valid: "success"
    })
});

module.exports = CloudTrailIsEnabledInAllRegions;