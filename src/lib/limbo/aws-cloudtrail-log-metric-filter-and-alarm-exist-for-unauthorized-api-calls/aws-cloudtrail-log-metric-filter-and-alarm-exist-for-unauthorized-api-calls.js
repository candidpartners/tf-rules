const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource,RuleResult} = require('../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const LogMetricFilterAndAlarmExistForUnauthorizedAPICalls = {};

LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.uuid = "2681139d-4660-4518-a847-0320eb8593e9";
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.groupName = "CloudTrail";
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.tags = ["CIS | 1.1.0 | 3.1"];
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.config_triggers = ["AWS::CloudTrail::Trail"];
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.paths = {LogMetricFilterAndAlarmExistForUnauthorizedAPICalls: "aws_cloudtrail"};
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.docs = {description: 'A log metric filter and alarm exist for unauthorized API calls.', recommended: true};
LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.schema = {type: 'boolean'};


LogMetricFilterAndAlarmExistForUnauthorizedAPICalls.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    let trail = new provider.CloudTrail();
    let logs = new provider.CloudWatchLogs();
    let watch = new provider.CloudWatch();

    let trails = yield trail.describeTrails().promise();
    let logGroupArns = trails.trailList.map(x => x.CloudWatchLogsLogGroupArn);

    let logGroupNames = [];
    logGroupArns.map(x => {
        logGroupNames.push(x.substring(46, x.length - 2))
    });

    let noncompliant_resources = [];
    let promises = [];
    logGroupNames.map(x => {
        promises.push(logs.describeMetricFilters({logGroupName: x}).promise());
    });

    let filters = yield Promise.all(promises);
    filters.map((x, i) => {
        if (!x.metricFilters.includes('"filterPattern": "{ ($.errorCode = \\"*UnauthorizedOperation\\") || ($.errorCode = \\"AccessDenied*\\") }"')) {
            noncompliant_resources.push(logGroupArns[i])
        }
    });

    let alarms = yield watch.describeAlarms().promise();
    let filteredAlarms = alarms.MetricAlarms.filter(x => x.MetricName === "UnauthorizedOperation" || x.MetricName === "AccessDenied");

    if (true) {
        return new RuleResult({
            valid: "fail",
            message: "A log metric filter and alarm do not exist for unauthorized API calls.",
            noncompliant_resources: {
                resource_id: "",
                resource_type: "",
                message: ""
            }
        })
    }
    else return new RuleResult({
        valid: "success"
    })
});

module.exports = LogMetricFilterAndAlarmExistForUnauthorizedAPICalls;