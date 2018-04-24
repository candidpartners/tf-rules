'use strict';
const {Resource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMNoInitialAccessKeys = {};

IAMNoInitialAccessKeys.uuid = "d26a454f-e759-4932-b95d-a5a2929b5c6d";
IAMNoInitialAccessKeys.groupName = "IAM";
IAMNoInitialAccessKeys.tags = [["CIS", "1.1.0", "1.23"]];
IAMNoInitialAccessKeys.config_triggers = ["AWS::IAM::User"];
IAMNoInitialAccessKeys.paths = {IAMNoInitialAccessKeys: "aws_iam_user"};
IAMNoInitialAccessKeys.docs = {description: 'Access keys should not be set up during initial IAM user setup.', recommended: false};
IAMNoInitialAccessKeys.schema = {
    type: 'object',
    properties: {
        enabled: {
            type: 'boolean',
            title: 'Enabled',
            default: true
        }
    }
};


IAMNoInitialAccessKeys.livecheck = async function (context) {
    let {config, provider} = context;

    let iam = new provider.IAM();
    let users = await iam.listUsers().promise();
    let userNames = users.Users.map(x => x.UserName);
    let initialKeyUsers = [];
    let accessKeys = [];

    for (let i = 0; i < userNames.length; i++) {
        let keys = await iam.listAccessKeys({UserName: userNames[i]}).promise();
        keys.AccessKeyMetadata.map(key => {
            accessKeys.push(key);
            if (key.CreateDate.toString() === users.Users[i].CreateDate.toString()) {
                initialKeyUsers.push(users.Users[i])
            }
        })
    }

    return new RuleResult({
        valid: (initialKeyUsers.length > 0) ? "fail" : "success",
        message: "Access keys should not be set up during initial IAM user setup.",
        resources: users.Users.map(user => {

            let initialKeyUser = initialKeyUsers.find(x => x.UserName === user.UserName);
            let initialKey;

            if (initialKeyUser) {
                initialKey = accessKeys.find(x => x.UserName === initialKeyUser.UserName);
            }

            return new Resource({
                is_compliant: initialKeyUser ? false : true,
                resource_id: user.UserName,
                resource_type: "AWS::IAM::User",
                message: initialKeyUser ? `has an access key ${initialKey.AccessKeyId} that was created on initial user creation.` : "does not have any access keys that were created on initial user creation."
            })
        })
    });
};

module.exports = IAMNoInitialAccessKeys;