'use strict';
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const Route53NoCloudjackVulnerabilities = {};

Route53NoCloudjackVulnerabilities.uuid = "6b9469b8-b356-4ab0-bac2-f73daf3fadc9";
Route53NoCloudjackVulnerabilities.groupName = "Route53";
Route53NoCloudjackVulnerabilities.tags = [["Candid", "1.0", "17"]];
Route53NoCloudjackVulnerabilities.config_triggers = ["AWS::Route53::Record"];
Route53NoCloudjackVulnerabilities.paths = {Route53NoCloudjackVulnerabilities: "aws_route53_zone"};
Route53NoCloudjackVulnerabilities.docs = {description: 'Route53 should be configured to avoid CloudJacking vulnerabilities.', recommended: true};
Route53NoCloudjackVulnerabilities.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: 'Enabled',
            default: true
        },
        route53GoodReferences: {
            type: 'boolean',
            title: 'All Route53 aliases reference a valid CloudFront distribution.',
            default: true
        },
        route53GoodCnames: {
            type: 'boolean',
            title: 'All referenced CloudFront distributions have a valid CNAME.',
            default: true
        }
    }
};


Route53NoCloudjackVulnerabilities.livecheck = async function (context) {
    let {config, provider} = context;

    let r53 = new provider.Route53();
    let zones = await r53.listHostedZones().promise();
    let badAliases = [];
    let missingCNAMES = false;
    let totalAliases = [];

    for (let i = 0; i < zones.HostedZones.length; i++) {
        let zoneId = zones.HostedZones[i].Id.substr(12, zones.HostedZones[i].Id.length);
        let recordSets = await r53.listResourceRecordSets({HostedZoneId: zoneId}).promise();

        let aliases = recordSets.ResourceRecordSets.filter(x => x.Type === "A");
        totalAliases.concat(aliases);
        let CNAMES = recordSets.ResourceRecordSets.filter(x => x.Type === "CNAME");

        aliases.map(alias => {
            if (!alias.AliasTarget) {
                badAliases.push(alias.Name);
            }
        });

        if (aliases.length !== CNAMES.length) {
            missingCNAMES = true;
        }
    }

    if (missingCNAMES) {
        return new RuleResult({
            valid: (badAliases.length > 0 || missingCNAMES) ? "fail" : "success",
            message: "Route53 should be configured to avoid CloudJacking vulnerabilities.",
            resources: [new Resource({
                is_compliant: false,
                resource_id: "Route 53",
                resource_type: "AWS::Route53::Record",
                message: "references one or more CloudFront distributions that do not have a valid CNAME."
            })]
        });
    }
    else {
        return new RuleResult({
            valid: (badAliases.length > 0 || missingCNAMES) ? "fail" : "success",
            message: "Route53 should be configured to avoid CloudJacking vulnerabilities.",
            resources: totalAliases.map(alias => {
                return new Resource({
                    is_compliant: (badAliases.includes(alias.Name)) ? false : true,
                    resource_id: alias.Name,
                    resource_type: "AWS::Route53::Record",
                    message: (badAliases.includes(alias.Name)) ? "does not reference a valid CloudFront distribution." : "references a valid CloudFront distribution."
                })
            })
        });
    }
};

module.exports = Route53NoCloudjackVulnerabilities;