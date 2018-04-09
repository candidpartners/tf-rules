'use strict';
const co = require('co');
const _ = require('lodash');
const debug = require('debug')('snitch/tag-format');
const {NonCompliantResource,RuleResult} = require('../../../rule-result');

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
CloudtrailLogsAreEncrypted.schema = { type: 'boolean' };


CloudtrailLogsAreEncrypted.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;

    let Cloud = new provider.CloudTrail();
    let trail = yield Cloud.describeTrails().promise();
    let trails = trail.trailList;
    let UnencryptedTrails = trails.filter(x => !x.hasOwnProperty("KmsKeyId"));

    if(UnencryptedTrails.length !== 0) {
        let noncompliant_resources = UnencryptedTrails.map(x => {
            return new NonCompliantResource({
                resource_id: x.TrailARN,
                resource_type: "AWS::CloudTrail::Trail",
                message: "is not encrypted."
            })
        });
        return new RuleResult({
            valid: "fail",
            message: "One or more CloudTrail logs are not encrypted.",
            noncompliant_resources
        })
    }
    else {
        return new RuleResult({ valid: "success" })
    }
});

module.exports = CloudtrailLogsAreEncrypted;

