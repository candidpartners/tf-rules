const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-cloudwatch-log-metric-filter-and-alarm-exist-for-unauthorized-api-calls');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("CloudTrail", "describeTrails", {trailList: [{CloudWatchLogsLogGroupArn: "arn:aws:logs:us-west-2:421471939647:log-group:MyTrail:*"}]});
GoodAWS.Service("CloudWatchLogs", "describeMetricFilters",
    {
        metricFilters: [
            {
                filterPattern: '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
                metricTransformations: [
                    {metricName: "MyMetric"}
                ]
            }
        ]
    }
);
GoodAWS.Service("CloudWatch", "describeAlarms", {
    MetricAlarms: [{
        MetricName: "MyMetric",
        AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest"]
    }]
});
GoodAWS.Service("SNS", "listSubscriptionsByTopic", {Subscriptions: [{Owner: "1234"}]});

let BadFilterAWS = new AWSPromiseMock();
BadFilterAWS.Service("CloudTrail", "describeTrails", {trailList: [{CloudWatchLogsLogGroupArn: "arn:aws:logs:us-west-2:421471939647:log-group:MyTrail:*"}]});
BadFilterAWS.Service("CloudWatchLogs", "describeMetricFilters", {metricFilters: []});
BadFilterAWS.Service("CloudWatch", "describeAlarms", {});
BadFilterAWS.Service("SNS", "listSubscriptionsByTopic", {});

let BadAlarmAWS = new AWSPromiseMock();
BadAlarmAWS.Service("CloudTrail", "describeTrails", {trailList: [{CloudWatchLogsLogGroupArn: "arn:aws:logs:us-west-2:421471939647:log-group:MyTrail:*"}]});
BadAlarmAWS.Service("CloudWatchLogs", "describeMetricFilters",
    {
        metricFilters: [
            {
                filterPattern: '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
                metricTransformations: [
                    {metricName: "MyMetric"}
                ]
            }
        ]
    }
);
BadAlarmAWS.Service("CloudWatch", "describeAlarms", {MetricAlarms: []});
BadAlarmAWS.Service("SNS", "listSubscriptionsByTopic", {});

let BadSubscriberAWS = new AWSPromiseMock();
BadSubscriberAWS.Service("CloudTrail", "describeTrails", {trailList: [{CloudWatchLogsLogGroupArn: "arn:aws:logs:us-west-2:421471939647:log-group:MyTrail:*"}]});
BadSubscriberAWS.Service("CloudWatchLogs", "describeMetricFilters",
    {
        metricFilters: [
            {
                filterPattern: '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
                metricTransformations: [
                    {metricName: "MyMetric"}
                ]
            }
        ]
    });
BadSubscriberAWS.Service("CloudWatch", "describeAlarms", {
    MetricAlarms: [{
        MetricName: "MyMetric",
        AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest"]
    }]
});
BadSubscriberAWS.Service("SNS", "listSubscriptionsByTopic", {Subscriptions: []});

describe("A log metric filter and alarm exist for unauthorized API calls.", () => {

    test("it fails because of no filter", async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;
        let result = await rule.livecheck({provider: BadFilterAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("A log metric filter and alarm do not exist for unauthorized API calls.")
    });
    test("it fails because of no alarm", async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;
        let result = await rule.livecheck({provider: BadAlarmAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("A log metric filter and alarm do not exist for unauthorized API calls.")
    });
    test("it fails because of no subscriber", async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;
        let result = await rule.livecheck({provider: BadSubscriberAWS});
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("A log metric filter and alarm do not exist for unauthorized API calls.")
    });

    test("it passes", async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;
        let result = await rule.livecheck({provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);