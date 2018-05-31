'use strict';
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const SnsEnsureAppropriateSubscribers = {};

SnsEnsureAppropriateSubscribers.uuid = "d6f9edbf-bb77-426e-a202-151c62a21dcf";
SnsEnsureAppropriateSubscribers.groupName = "SNS";
SnsEnsureAppropriateSubscribers.tags = [["CIS", "1.1.0", "3.15"]];
SnsEnsureAppropriateSubscribers.config_triggers = ["AWS::::Account"];
SnsEnsureAppropriateSubscribers.paths = {SnsEnsureAppropriateSubscribers: "aws_sns_topic"};
SnsEnsureAppropriateSubscribers.docs = {description: 'The list of subscribers to all SNS topics should adhere to the provided configuration whitelist and/or blacklist.', recommended: false};
SnsEnsureAppropriateSubscribers.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: 'Enabled',
            default: true
        },
        global_whitelist: { // Users in this list can be subscribed to any topic
            type: 'array',
            title: 'Global Whitelist',
            items: {
                type: 'string'
            }
        },
        topics: {
            type: 'array',
            title: 'SNS Topics',
            items: {
                type: 'object',
                properties: {
                    topic_arn: {
                        type: 'string',
                        title: 'Topic ARN'
                    },
                    topic_whitelist: { // Only users that are in this list should be subscribed to this topic
                        type: 'array',
                        title: 'Topic Whitelist',
                        items: {
                            type: 'string'
                        }
                    }
                }
            }
        }
    }
};


SnsEnsureAppropriateSubscribers.livecheck = async function (context) {
    let {config, provider} = context;

    let sns = new provider.SNS();
    let topics = await sns.listTopics().promise();
    let whitelisted_subscribers = config.global_whitelist;
    let bad_subscriptions = [];

    for (let i = 0; i < topics.Topics.length; i++) {

        let config_topic = config.topics.find(x => x.topic_arn === topics.Topics[i].TopicArn);
        let topic_subscriptions = await sns.listSubscriptionsByTopic({TopicArn: topics.Topics[i].TopicArn}).promise();

        let topic_whitelist = [];
        if (config_topic)
            topic_whitelist = config_topic.topic_whitelist;

        topic_subscriptions.Subscriptions.map(subscription => {
            if (!topic_whitelist.includes(subscription.Endpoint) && !whitelisted_subscribers.includes(subscription.Endpoint)) {
                bad_subscriptions.push(subscription);
            }
        })
    }


    return new RuleResult({
        valid: (bad_subscriptions.length > 0) ? "fail" : "success",
        message: "Only specified users should be subscribed to each SNS topic.",
        resources: topics.Topics.map(topic => {
            let unneeded_subscriptions = bad_subscriptions.filter(x => x.TopicArn === topic.TopicArn);

            return new Resource({
                is_compliant: (unneeded_subscriptions.length > 0) ? false : true,
                resource_id: topic.TopicArn,
                resource_type: "AWS::::Account",
                message: (unneeded_subscriptions.length > 0) ? `has unapproved subscribers ${unneeded_subscriptions.map(x => x.Endpoint)}.` : "has only approved subscribers."
            })
        })
    });
};

module.exports = SnsEnsureAppropriateSubscribers;