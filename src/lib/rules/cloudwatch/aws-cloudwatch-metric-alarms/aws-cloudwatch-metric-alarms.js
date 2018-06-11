// @flow
const _ = require('lodash');
const Papa = require('papaparse');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const CloudWatchMetricAlarms = {};

CloudWatchMetricAlarms.uuid = "2681139d-4660-4518-a847-0320eb8593e9";
CloudWatchMetricAlarms.groupName = "CloudWatch";
CloudWatchMetricAlarms.tags = [
    ["CIS", "1.1.0", "3.1"],
    ["CIS", "1.1.0", "3.2"],
    ["CIS", "1.1.0", "3.3"],
    ["CIS", "1.1.0", "3.4"],
    ["CIS", "1.1.0", "3.5"],
    ["CIS", "1.1.0", "3.6"],
    ["CIS", "1.1.0", "3.7"],
    ["CIS", "1.1.0", "3.8"],
    ["CIS", "1.1.0", "3.9"],
    ["CIS", "1.1.0", "3.10"],
    ["CIS", "1.1.0", "3.11"],
    ["CIS", "1.1.0", "3.12"],
    ["CIS", "1.1.0", "3.13"],
    ["CIS", "1.1.0", "3.14"],
    ["NIST", "AC", "2g"],
    ["NIST", "AC", "2(1)"]
];
CloudWatchMetricAlarms.config_triggers = ["AWS::CloudWatch::Alarm"];
CloudWatchMetricAlarms.paths = {LogMetricFilterAndAlarmExistForUnauthorizedAPICalls: "aws_cloudwatch_metric_alarm"};
CloudWatchMetricAlarms.docs = {
    description: 'A log metric filter and alarm should exist for all rules.',
    recommended: true
};
CloudWatchMetricAlarms.schema = {
    type: 'object',
    properties: {
        UnauthorizedAPICalls: {type: 'boolean', title: "Unauthorized API calls", default: false},
        ManagementConsoleSignInWithoutMFA: {type: 'boolean', title: "Management console sign in without MFA", default: false},
        UsageOfRootAccount: {type: 'boolean', title: "Usage of root account", default: false},
        IAMPolicyChanges: {type: 'boolean', title: "IAM policy changes", default: false},
        IAMAccessKeyCreation: {type: 'boolean', title: "IAM access key creation", default: false},
        IAMUserCreation: {type: 'boolean', title: "IAM user creation", default: false},
        CloudTrailConfigurationChanges: {type: 'boolean', title: "CloudTrail configuration changes", default: false},
        AWSManagementConsoleAuthenticationFailures: {type: 'boolean', title: "AWS management console authentication failure", default: false},
        DisablingOrScheduledDeletionOfCustomerCreatedCMKs: {type: 'boolean', title: "disabling or scheduled deletion of customer created CMKs", default: false},
        S3BucketPolicyChanges: {type: 'boolean', title: "S3 bucket policy changes", default: false},
        AWSConfigConfigurationChanges: {type: 'boolean', title: "AWS Config configuration changes", default: false},
        SecurityGroupChanges: {type: 'boolean', title: "Security group changes", default: false},
        ChangesToNetworkAccessControlLists: {type: 'boolean', title: "Changes to network access control lists", default: false},
        ChangesToNetworkGateways: {type: 'boolean', title: "Changes to network gateways", default: false},
        RouteTableChanges: {type: 'boolean', title: "Route table changes", default: false},
        VPCChanges: {type: 'boolean', title: "VPC changes", default: false}
    }
};

const filterPatterns = [
    {
        config: "UnauthorizedAPICalls",
        rule: 'unauthorized API calls',
        pattern: '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }'
    },
    {
        config: "ManagementConsoleSignInWithoutMFA",
        rule: 'management console sign-in without MFA',
        pattern: '{ ($.eventName = ConsoleLogin) && ($.additionalEventData.MFAUsed != "Yes") }'
    },
    {
        config: "UsageOfRootAccount",
        rule: 'usage of root account',
        pattern: '{ ($.userIdentity.type = "Root") && ($.userIdentity.invokedBy NOTEXISTS) && ($.eventType != "AwsServiceEvent") }'
    },
    {
        config: "IAMPolicyChanges",
        rule: 'IAM policy changes',
        pattern: '{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }'
    },
    {
        config: "IAMAccessKeyCreation",
        rule: "IAM Access Key Creation",
        pattern: '{ ($.eventName = CreateAccessKey) }'
    },
    {
        config: "IAMUserCreation",
        rule: "IAM User Creation",
        pattern: '{ ($.eventName = CreateUser) }'
    },
    {
        config: "CloudTrailConfigurationChanges",
        rule: 'CloudTrail configuration changes',
        pattern: '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) ||($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }'
    },
    {
        config: "AWSManagementConsoleAuthenticationFailures",
        rule: 'AWS management console authentication failures',
        pattern: '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failedauthentication") }'
    },
    {
        config: "DisablingOrScheduledDeletionOfCustomerCreatedCMKs",
        rule: 'disabling or scheduled deletion of customer created CMKs',
        pattern: '{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }'
    },
    {
        config : "S3BucketPolicyChanges",
        rule: 'S3 bucket policy changes',
        pattern: '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }'
    },
    {
        config: "AWSConfigConfigurationChanges",
        rule: 'AWS Config configuration changes',
        pattern: '{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }'
    },
    {
        config: "SecurityGroupChanges",
        rule: 'security group changes',
        pattern: '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }'
    },
    {
        config: "ChangesToNetworkAccessControlLists",
        rule: 'changes to Network Access Control Lists',
        pattern: '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }'
    },
    {
        config: "ChangesToNetworkGateways",
        rule: 'changes to network gateways',
        pattern: '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }'
    },
    {
        config: "RouteTableChanges",
        rule: 'route table changes',
        pattern: '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }'
    },
    {
        config: "VPCChanges",
        rule: 'VPC changes',
        pattern: '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }'
    },
];


CloudWatchMetricAlarms.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */{
    let {config, provider} = context;
    let trail = new provider.CloudTrail();
    let logs = new provider.CloudWatchLogs();
    let watch = new provider.CloudWatch();
    let sns = new provider.SNS();

    let resources = [];

    // Get the names of all the CloudTrail log groups
    let trails = await trail.describeTrails().promise();
    let logGroupArns = trails.trailList.map(x => x.CloudWatchLogsLogGroupArn);

    let logGroupNames = [];
    logGroupArns.map(x => {
        logGroupNames.push(x.substring(46, x.length - 2))
    });

    // Get all the metric filters in those log groups
    let promises = [];
    logGroupNames.map(x => {
        promises.push(logs.describeMetricFilters({logGroupName: x}).promise());
    });
    let metricFilters = await Promise.all(promises);

    // Get the names of all the metric filters that match a rule pattern
    let patterns = filterPatterns.map(x => x.pattern);
    let metrics = metricFilters[0].metricFilters.filter(x => patterns.includes(x.filterPattern));
    let metricNames = metrics.map(x => x.metricTransformations[0].metricName);

    // Get all the alarms under those metric filters
    let result = await watch.describeAlarms().promise();
    let alarms = result.MetricAlarms;
    while (result.NextToken) {
        result = await watch.describeAlarms({NextToken: result.NextToken}).promise();
        alarms = [...alarms, ...result.MetricAlarms]
    }

    // Check if no metric filters exist
    if (metrics.length === 0) {
        resources.push(new Resource({
            is_compliant: false,
            resource_id: "CloudWatchLogs",
            resource_type: "AWS::CloudWatch::Alarm",
            message: "does not have any metric filters set up."
        }));
        return new RuleResult({
            valid: "fail",
            message: `A log metric filter and alarm do not exist for any rules.`,
            resources: resources
        })
    }

    // Filter to only check the rules specified in the config
    let activeFilterPatterns = filterPatterns.filter(filterPattern => config[filterPattern.config]);

    for (let i = 0; i < activeFilterPatterns.length; i++) {

        for (let j = 0; j < metricNames.length; j++) {


            let activeFilter = metricFilters[0].metricFilters.find(x => x.filterPattern === activeFilterPatterns[i].pattern);
            let filteredAlarm = undefined;
            let topicArn = undefined;
            let subscribers = undefined;

            if (alarms) {
                filteredAlarm = alarms.find(x => x.MetricName === metricNames[j]);
            }
            if (filteredAlarm) {
                topicArn = filteredAlarm.AlarmActions[0];
            }
            if (topicArn) {
                subscribers = await sns.listSubscriptionsByTopic({TopicArn: topicArn}).promise();
            }


            // Check if no metric filters exist for the specified rule
            if (activeFilter === undefined) {
                resources.push(new Resource({
                    is_compliant: false,
                    resource_id: "CloudWatch",
                    resource_type: "AWS::CloudWatch::Alarm",
                    message: `does not have a metric filter set up for ${activeFilterPatterns[i].rule}.`
                }));
            }

            // Check if no alarms exist for the specified filter
            else if (filteredAlarm === undefined) {
                resources.push(new Resource({
                    is_compliant: false,
                    resource_id: "CloudWatch",
                    resource_type: "AWS::CloudWatch::Alarm",
                    message: `does not have an alarm linked to the metric filter for ${activeFilterPatterns[i].rule}.`
                }));
            }

            // Check if no actions exist for the specified alarm
            else if (filteredAlarm.AlarmActions.length === 0) {
                resources.push(new Resource({
                    is_compliant: false,
                    resource_id: "CloudWatch",
                    resource_type: "AWS::CloudWatch::Alarm",
                    message: `does not have an action linked to the alarm for ${activeFilterPatterns[i].rule}.`
                }));
            }

            // Check if no subscriptions exist for the specified alarm
            else if (_.get(subscribers,'Subscriptions.length') === 0) {
                resources.push(new Resource({
                    is_compliant: false,
                    resource_id: "CloudWatch",
                    resource_type: "AWS::CloudWatch::Alarm",
                    message: `does not have any subscribers linked to the alarm for ${activeFilterPatterns[i].rule}.`
                }));
            }

            // Otherwise it is compliant
            else {
                resources.push(new Resource({
                    is_compliant: true,
                    resource_id: "Cloudwatch",
                    resource_type: "AWS::Cloudwatch::Alarm",
                    message: `has a metric filter set up and fully configured for ${activeFilterPatterns[i].rule}.`
                }));
            }
        }
    }

    return new RuleResult({
        valid: (resources.filter(x => x.is_compliant === false).length > 0) ? "fail" : "success",
        message: "A log metric filter and alarm should exist for all rules.",
        resources: resources
    })

};

module.exports = CloudWatchMetricAlarms;