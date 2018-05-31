const AWS = require('aws-sdk');
const AWSPromiseMock = require('../../../../aws-promise-mock');
const rule = require('./aws-sns-ensure-appropriate-subscribers');

let GoodAWS = new AWSPromiseMock();
GoodAWS.Service("SNS", "listTopics", {
    "Topics": [
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:CIS-NotificationTopic"
        },
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:prd"
        },
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:suntrust-test-elasticache-notifications"
        },
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:test"
        },
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:test-app-code"
        },
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:tst"
        }
    ]
});
GoodAWS.Service("SNS", "listSubscriptionsByTopic", {
    "Subscriptions": [
        {
            "SubscriptionArn": "arn:aws:sns:us-west-2:421471939647:CIS_monitoring_alarms:322b0cae-c415-4537-8eae-617b2769a945",
            "Owner": "421471939647",
            "Protocol": "email",
            "Endpoint": "ethan.bower@candidpartners.com",
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:test"
        }
    ]
});

let BadAWS = new AWSPromiseMock();
BadAWS.Service("SNS", "listTopics", {
    "Topics": [
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:CIS-NotificationTopic"
        },
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:prd"
        },
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:suntrust-test-elasticache-notifications"
        },
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:test"
        },
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:test-app-code"
        },
        {
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:tst"
        }
    ]
});
BadAWS.Service("SNS", "listSubscriptionsByTopic", {
    "Subscriptions": [
        {
            "SubscriptionArn": "arn:aws:sns:us-west-2:421471939647:CIS_monitoring_alarms:322b0cae-c415-4537-8eae-617b2769a945",
            "Owner": "421471939647",
            "Protocol": "email",
            "Endpoint": "ethan.bower@candidpartners.com",
            "TopicArn": "arn:aws:sns:us-west-2:421471939647:test"
        }
    ]
});

describe("SNS topics have only approved subscribers.", () => {

    test("It fails", async () => {
        let result = await rule.livecheck({config: {global_whitelist: [], topics: [
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:CIS-NotificationTopic"
                    },
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:prd"
                    },
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:suntrust-test-elasticache-notifications"
                    },
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:test"
                    },
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:test-app-code"
                    },
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:tst"
                    }
                ]}, provider: BadAWS});
        expect(result.valid).toBe('fail');
    });

    test("It passes", async () => {
        let result = await rule.livecheck({config: {global_whitelist: ["ethan.bower@candidpartners.com"], topics: [
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:CIS-NotificationTopic"
                    },
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:prd"
                    },
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:suntrust-test-elasticache-notifications"
                    },
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:test"
                    },
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:test-app-code"
                    },
                    {
                        "TopicArn": "arn:aws:sns:us-west-2:421471939647:tst"
                    }
                ]}, provider: GoodAWS});
        expect(result.valid).toBe('success');
    });
}, 10000);