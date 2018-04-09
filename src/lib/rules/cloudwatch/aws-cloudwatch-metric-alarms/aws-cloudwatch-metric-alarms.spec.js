const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-cloudwatch-metric-alarms');

// Should fail because no filters at all
let BadFiltersAWS = new AWSPromiseMock();
BadFiltersAWS.Service("CloudTrail", "describeTrails", {trailList: [{CloudWatchLogsLogGroupArn: "arn:aws:logs:us-west-2:421471939647:log-group:MyTrail:*"}]});
BadFiltersAWS.Service("CloudWatchLogs", "describeMetricFilters", {metricFilters: []});
BadFiltersAWS.Service("CloudWatch", "describeAlarms", {});
BadFiltersAWS.Service("SNS", "listSubscriptionsByTopic", {});


// Should fail because no filter for the specific rule
let BadFilterAWS = new AWSPromiseMock();
BadFilterAWS.Service("CloudTrail", "describeTrails", {trailList: [{CloudWatchLogsLogGroupArn: "arn:aws:logs:us-west-2:421471939647:log-group:MyTrail:*"}]});
BadFilterAWS.Service("CloudWatchLogs", "describeMetricFilters", {
    metricFilters: [
        {
            filterPattern: '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failedauthentication") }',
            metricTransformations: [
                {metricName: "MyMetric"}
            ]
        },
        {
            filterPattern: '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
            metricTransformations: [
                {metricName: "MyMetric2"}
            ]
        }
    ]
});
BadFilterAWS.Service("CloudWatch", "describeAlarms", {});
BadFilterAWS.Service("SNS", "listSubscriptionsByTopic", {});


// Should fail because no alarm for the rule
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


// Should fail because no alarm actions
let BadActionAWS = new AWSPromiseMock();
BadActionAWS.Service("CloudTrail", "describeTrails", {trailList: [{CloudWatchLogsLogGroupArn: "arn:aws:logs:us-west-2:421471939647:log-group:MyTrail:*"}]});
BadActionAWS.Service("CloudWatchLogs", "describeMetricFilters",
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
BadActionAWS.Service("CloudWatch", "describeAlarms", {MetricAlarms: [{MetricName: "MyMetric", AlarmActions: []}]});
BadActionAWS.Service("SNS", "listSubscriptionsByTopic", {});


// Should fail because no subscribers
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

// Should pass all tests
let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("CloudTrail", "describeTrails", {trailList: [{CloudWatchLogsLogGroupArn: "arn:aws:logs:us-west-2:421471939647:log-group:MyTrail:*"}]});
GoodAWS.Service("CloudWatchLogs", "describeMetricFilters",
    {
        metricFilters: [
            {
                filterPattern: '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
                metricTransformations: [
                    {metricName: "MyMetric1"}
                ]
            },
            {
                filterPattern: '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }',
                metricTransformations: [
                    {metricName: "MyMetric2"}
                ]
            },
            {
                filterPattern: '{ ($.userIdentity.type = "Root") && ($.userIdentity.invokedBy NOTEXISTS) && ($.eventType != "AwsServiceEvent") }',
                metricTransformations: [
                    {metricName: "MyMetric3"}
                ]
            },
            {
                filterPattern: '{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }',
                metricTransformations: [
                    {metricName: "MyMetric4"}
                ]
            },
            {
                filterPattern: '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) ||($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }',
                metricTransformations: [
                    {metricName: "MyMetric5"}
                ]
            },
            {
                filterPattern: '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failedauthentication") }',
                metricTransformations: [
                    {metricName: "MyMetric6"}
                ]
            },
            {
                filterPattern: '{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }',
                metricTransformations: [
                    {metricName: "MyMetric7"}
                ]
            },
            {
                filterPattern: '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }',
                metricTransformations: [
                    {metricName: "MyMetric8"}
                ]
            },
            {
                filterPattern: '{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }',
                metricTransformations: [
                    {metricName: "MyMetric9"}
                ]
            },
            {
                filterPattern: '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }',
                metricTransformations: [
                    {metricName: "MyMetric10"}
                ]
            },
            {
                filterPattern: '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }',
                metricTransformations: [
                    {metricName: "MyMetric11"}
                ]
            },
            {
                filterPattern: '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }',
                metricTransformations: [
                    {metricName: "MyMetric12"}
                ]
            },
            {
                filterPattern: '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }',
                metricTransformations: [
                    {metricName: "MyMetric13"}
                ]
            },
            {
                filterPattern: '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }',
                metricTransformations: [
                    {metricName: "MyMetric14"}
                ]
            },
        ]
    }
);
GoodAWS.Service("CloudWatch", "describeAlarms", {
    MetricAlarms: [
        {
            MetricName: "MyMetric1",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest"]
        },
        {
            MetricName: "MyMetric2",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest2"]
        },
        {
            MetricName: "MyMetric3",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest3"]
        },
        {
            MetricName: "MyMetric4",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest4"]
        },
        {
            MetricName: "MyMetric5",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest5"]
        },
        {
            MetricName: "MyMetric6",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest6"]
        },
        {
            MetricName: "MyMetric7",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest7"]
        },
        {
            MetricName: "MyMetric8",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest8"]
        },
        {
            MetricName: "MyMetric9",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest9"]
        },
        {
            MetricName: "MyMetric10",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest10"]
        },
        {
            MetricName: "MyMetric11",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest11"]
        },
        {
            MetricName: "MyMetric12",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest12"]
        },
        {
            MetricName: "MyMetric13",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest13"]
        },
        {
            MetricName: "MyMetric14",
            AlarmActions: ["arn:aws:sns:us-west-2:421471939647:CISRulesTest14"]
        }
    ]
});
GoodAWS.Service("SNS", "listSubscriptionsByTopic", {Subscriptions: [{Owner: "1234"}]});


describe("A log metric filter and alarm exist for all rules.", () => {

    test("it fails because of no filters", async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;
        let result = await rule.livecheck({
            config: {UnauthorizedAPICalls: true, VPCChanges: true},
            provider: BadFiltersAWS
        });
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("A log metric filter and alarm do not exist for any rules.")
    });
    test("it fails because of no filter for the rule", async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;
        let result = await rule.livecheck({
            config: {
                UnauthorizedAPICalls: true,
                ManagementConsoleSignInWithoutMFA: true,
                UsageOfRootAccount: true
            }, provider: BadFilterAWS
        });
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("A log metric filter and alarm do not exist for one or more rules.")
    });
    test("it fails because of no alarm for the rule", async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;
        let result = await rule.livecheck({
            config: {
                UnauthorizedAPICalls: true,
                ManagementConsoleSignInWithoutMFA: true,
                UsageOfRootAccount: true,
                IAMPolicyChanges: true,
            }, provider: BadAlarmAWS
        });
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("A log metric filter and alarm do not exist for one or more rules.")
    });
    test("it fails because of no alarm action", async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;
        let result = await rule.livecheck({
            config: {
                UnauthorizedAPICalls: true,
                ManagementConsoleSignInWithoutMFA: true,
                UsageOfRootAccount: true,
                IAMPolicyChanges: true,
                CloudTrailConfigurationChanges: true
            }, provider: BadActionAWS
        });
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("A log metric filter and alarm do not exist for one or more rules.")
    });
    test("it fails because of no subscriber", async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;
        let result = await rule.livecheck({
            config: {
                UnauthorizedAPICalls: true,
                ManagementConsoleSignInWithoutMFA: true,
                UsageOfRootAccount: true,
                IAMPolicyChanges: true,
                ChangesToNetworkGateways: true,
                RouteTableChanges: true
            }, provider: BadSubscriberAWS
        });
        expect(result.valid).toBe('fail');
        expect(result.message).toBe("A log metric filter and alarm do not exist for one or more rules.")
    });

    test("it passes", async () => {
        jasmine.DEFAULT_TIMEOUT_INTERVAL = 50000;
        let result = await rule.livecheck({
            config: {
                UnauthorizedAPICalls: true,
                ManagementConsoleSignInWithoutMFA: true,
                UsageOfRootAccount: true,
                IAMPolicyChanges: true,
                CloudTrailConfigurationChanges: true,
                AWSManagementConsoleAuthenticationFailures: true,
                DisablingOrScheduledDeletionOfCustomerCreatedCMKs: true,
                S3BucketPolicyChanges: true,
                AWSConfigConfigurationChanges: true,
                SecurityGroupChanges: true,
                ChangesToNetworkAccessControlLists: true,
                ChangesToNetworkGateways: true,
                RouteTableChanges: true,
                VPCChanges: true
            }, provider: GoodAWS
        });
        expect(result.valid).toBe('success');
    });
}, 10000);