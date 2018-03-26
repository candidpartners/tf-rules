'use strict';
const AWS = require('aws-sdk');
const co = require('co');
const _ = require('lodash');
const debug = require('debug')('snitch/tag-exists');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const EC2TagExists = {};

EC2TagExists.uuid = "cb6da3e8-cff5-490c-b200-4d43f8cc0632";
EC2TagExists.groupName = "EC2";

EC2TagExists.docs = {
    description: "Required tagging must exist",
    recommended: false
};

EC2TagExists.schema = {
    type: 'array',
    items: {
        type: 'string'
    }
};

EC2TagExists.paths = {
    awsInstance: 'aws_instance'
};

EC2TagExists.livecheck = co.wrap(function* (context) {
    let ec2 = new context.provider.EC2();

    function getEC2s(params) {
        return ec2.describeInstances(params).promise();
    }

    let result = yield getEC2s({});
    let Reservations = result.Reservations;

    while (result.NextToken) {
        result = yield getEC2s({NextToken: result.NextToken});
        Reservations.push(result.Reservations);
    }

    let Instances = _.flatMap(Reservations, res => res.Instances);
    let NoInstanceTags = Instances.filter(x => !x.TagKey);

    if (NoInstanceTags.length > 0)
        return {valid: 'fail', message: "One or more of your EC2 instances do not have an Instance Tag."};
    else
        return {valid: 'success'};
});

EC2TagExists.validate = function (context) {
    let result = null;
    let tagSpec = null;
    let reqTags = [];
    let message = [];
    debug('Config: %j', context.config);
    for (let tagSpec of context.config) {
        reqTags.push(tagSpec);
        debug('Tag: %j', tagSpec)
    }
    debug('Tag List: %j', reqTags);
    let missingTags = [];
    missingTags = _.difference(reqTags, _.keys(context.instance.tags));
    debug('Missing Tags: %j', missingTags);
    for (let item of missingTags) {
        message.push(item + ' tag is missing')
    }
    if (missingTags.length == 0) {
        result = {
            valid: 'success',
        };
    } else {
        result = {
            valid: 'fail',
            message
        };
    }
    return result;
};

module.exports = EC2TagExists;

