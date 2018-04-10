// @flow
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudTrailTrailsAreIntegratedWithCloudWatchLogs = {};

CloudTrailTrailsAreIntegratedWithCloudWatchLogs.uuid = "f030c67a-48b2-4499-bbec-c14c7798e8a0";
CloudTrailTrailsAreIntegratedWithCloudWatchLogs.groupName = "CloudTrail";
CloudTrailTrailsAreIntegratedWithCloudWatchLogs.tags = [["CIS", "1.1.0", "2.4"]];
CloudTrailTrailsAreIntegratedWithCloudWatchLogs.config_triggers = ["AWS::CloudTrail::Trail"];
CloudTrailTrailsAreIntegratedWithCloudWatchLogs.paths = {CloudTrailTrailsAreIntegratedWithCloudWatchLogs: "aws_cloudtrail"};
CloudTrailTrailsAreIntegratedWithCloudWatchLogs.docs = {
    description: 'All CloudTrail trails are integrated with CloudWatch logs.',
    recommended: true
};
CloudTrailTrailsAreIntegratedWithCloudWatchLogs.schema = {
    type: 'boolean',
    default: true
};


CloudTrailTrailsAreIntegratedWithCloudWatchLogs.livecheck = async function (context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;
    let trail = new provider.CloudTrail();

    let trails = await trail.describeTrails().promise();
    let noncompliant_resources = [];
    let compliant_resources = [];
    let promises = [];

    trails.trailList.map(tr => {
        promises.push(trail.getTrailStatus({Name: tr.Name}).promise());
    });

    let status = await Promise.all(promises);

    trails.trailList.map(tr => {
        status.map(x => {
            let latestDate = new Date(x.LatestCloudWatchLogsDeliveryTime);
            let today = new Date();
            if ((today - latestDate) > 86400000)
                noncompliant_resources.push(tr)
            else
                compliant_resources.push(tr)
        })
    });

    let bad_resources = noncompliant_resources.map(x => {

        return new Resource({
            is_compliant: false,
            resource_id: x.Name,
            resource_type: "AWS::CloudTrail::Trail",
            message: "is not integrated with CloudWatch logs."
        })
    });

    let good_resources = compliant_resources.map(x => {
        return new Resource({
            is_compliant: true,
            resource_id: x.Name,
            resource_type: "AWS::CloudTrail::Trail",
            message: "is integrated with CloudWatch logs."
        })
    })

    return new RuleResult({
        valid: (noncompliant_resources.length > 0) ? "fail" : "success",
        message: CloudTrailTrailsAreIntegratedWithCloudWatchLogs.docs.description,
        resources: [...good_resources,...bad_resources],
    })

};

module.exports = CloudTrailTrailsAreIntegratedWithCloudWatchLogs;