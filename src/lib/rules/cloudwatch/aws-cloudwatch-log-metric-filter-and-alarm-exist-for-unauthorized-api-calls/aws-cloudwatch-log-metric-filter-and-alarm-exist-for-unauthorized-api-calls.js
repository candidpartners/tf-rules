const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource,RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const LogMetricFilterAndAlarmExistForUnauthorizedAPICalls = {};

LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.uuid = "2681139d-4660-4518-a847-0320eb8593e9";
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.groupName = "CloudWatch";
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.tags = ["CIS | 1.1.0 | 3.1"];
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.config_triggers = ["AWS::CloudWatch::Alarm"];
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.paths = {LogMetricFilterAndAlarmExistForUnauthorizedAPICalls: "aws_cloudwatch_metric_alarm"};
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.docs = {description: 'A log metric filter and alarm exist for unauthorized API calls.', recommended: true};
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.schema = {type: 'boolean'};


LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let trail = new provider.CloudTrail();
    let logs = new provider.CloudWatchLogs();
    let watch = new provider.CloudWatch();
    let sns = new provider.SNS();

    let trails = yield trail.describeTrails().promise();
    let logGroupArns = trails.trailList.map(x => x.CloudWatchLogsLogGroupArn);

    let logGroupNames = [];
    logGroupArns.map(x => {
        logGroupNames.push(x.substring(46, x.length - 2))
    });

    let promises = [];
    logGroupNames.map(x => {
        promises.push(logs.describeMetricFilters({logGroupName: x}).promise());
    });

    let filters = yield Promise.all(promises);
    if (filters[0].metricFilters.length === 0) {
        return new RuleResult({
            valid: "fail",
            message: "A log metric filter and alarm do not exist for unauthorized API calls.",
            noncompliant_resources: [new NonCompliantResource({
                resource_id: "CloudWatchLogs",
                resource_type: "AWS::CloudWatch::Alarm",
                message: "does not have a metric filter set up for unauthorized API call."
            })]
        })
    }
    else {

        let filter = filters[0].metricFilters.find(x => x.filterPattern === '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }');
        let metricName = filter.metricTransformations[0].metricName;

        let result = yield watch.describeAlarms().promise();
        let alarms = result.MetricAlarms;

        while (result.NextToken) {
            result = yield watch.describeAlarms({NextToken: result.NextToken}).promise();
            alarms = [...alarms, ...result.MetricAlarms]
        }

        let filteredAlarm = alarms.find(x => x.MetricName === metricName);
        if (!filteredAlarm) {
            return new RuleResult({
                valid: "fail",
                message: "A log metric filter and alarm do not exist for unauthorized API calls.",
                noncompliant_resources: [new NonCompliantResource({
                    resource_id: "CloudWatch",
                    resource_type: "AWS::CloudWatch::Alarm",
                    message: "does not have an alarm set up for the metric filter for unauthorized API call."
                })]
            })
        }
        else {

            if (filteredAlarm.AlarmActions.length === 0) {
                return new RuleResult({
                    valid: "fail",
                    message: "A log metric filter and alarm do not exist for unauthorized API calls.",
                    noncompliant_resources: [new NonCompliantResource({
                        resource_id: "CloudWatch",
                        resource_type: "AWS::CloudWatch::Alarm",
                        message: "does not have an alarm set up for the metric filter for unauthorized API call."
                    })]
                })
            }

            else {

                let topicArn = filteredAlarm.AlarmActions[0];
                let subscribers = yield sns.listSubscriptionsByTopic({TopicArn: topicArn}).promise();

                if (subscribers.Subscriptions.length === 0) {
                    return new RuleResult({
                        valid: "fail",
                        message: "A log metric filter and alarm do not exist for unauthorized API calls.",
                        noncompliant_resources: [new NonCompliantResource({
                            resource_id: "CloudWatch",
                            resource_type: "AWS::CloudWatch::Alarm",
                            message: "does not have a subscriber set up for the alarm for unauthorized API calls."
                        })]
                    })
                }
                else return new RuleResult({
                    valid: "success"
                })
            }
        }
    }
});

module.exports = LogMetricFilterAndAlarmExistForUnauthorizedAPICalls;