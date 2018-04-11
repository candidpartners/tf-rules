// @flow
const Papa = require('papaparse');
const _ = require('lodash');
const {Resource, RuleResult, Context} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMEnsureUnusedCredentialsAreDisabled = {};

IAMEnsureUnusedCredentialsAreDisabled.uuid = "944996af-32cd-4af6-9bb2-03819a631b44";
IAMEnsureUnusedCredentialsAreDisabled.groupName = "IAM";
IAMEnsureUnusedCredentialsAreDisabled.tags = [["CIS", "1.1.0", "1.3"]];
IAMEnsureUnusedCredentialsAreDisabled.config_triggers = ["AWS::IAM::User"];
IAMEnsureUnusedCredentialsAreDisabled.paths = {IAMEnsureUnusedCredentialsAreDisabled: "aws_iam_user"};
IAMEnsureUnusedCredentialsAreDisabled.docs = {
    description: 'Credentials unused for at least 90 days are disabled.',
    recommended: false
};
IAMEnsureUnusedCredentialsAreDisabled.schema = {type: 'number', default: 90};


IAMEnsureUnusedCredentialsAreDisabled.livecheck = async function(context /*: Context */) /*: Promise<RuleResult> */ {
    let {config, provider} = context;
    const IAM = new context.provider.IAM();

    // Get credential report
    await IAM.generateCredentialReport().promise();
    let report = await IAM.getCredentialReport().promise();

    let content = report.Content.toString();
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    let dateRange = config;

    function getDaysAgo(date) {
        let givenDate = new Date(date);
        let currentDate = new Date();
        let XDaysAgoInMS = 86400000; //1 Day == 86,400,000 ms
        let differenceInMS = Math.abs(givenDate - currentDate);
        return differenceInMS / XDaysAgoInMS;
    }

    function userIsValid(user) {
        let {password_enabled, password_last_used} = user;
        if (password_enabled !== 'true')
            return true;
        else
            return getDaysAgo(new Date(password_last_used)) < dateRange;
    }

    function userAccessKeysAreValid(user) {
        let {
            access_key_1_active,
            access_key_1_last_used_date,
            access_key_2_active,
            access_key_2_last_used_date
        } = user;

        let isAccessKeyValid = (key_active, last_used) => key_active === 'false' || getDaysAgo(last_used) < dateRange;

        return isAccessKeyValid(access_key_1_active, access_key_1_last_used_date) &&
            isAccessKeyValid(access_key_2_active, access_key_2_last_used_date);
    }

    let invalidPasswordUsers = data.filter(x => !userIsValid(x));
    let invalidAccessKeyUsers = data.filter(x => !userAccessKeysAreValid(x));

    return new RuleResult({
        valid: (invalidPasswordUsers.length > 0 || invalidAccessKeyUsers.length > 0) ? "fail" : "success",
        message: "Users must have a valid password and access key",
        resources: data.map(user => {
            let validPassword = userIsValid(user);
            let validAccessKeys = userAccessKeysAreValid(user);

            let message = "";
            if(validPassword && validAccessKeys)
                message = "User has a valid password and access keys.";
            if(!validPassword)
                message += `User has a password they have not used in over ${dateRange} days. `;
            if(!validAccessKeys)
                message += `User has an access key they have not used in over ${dateRange} days.`;
            return new Resource({
                is_compliant: (validPassword && validAccessKeys),
                message,
                resource_id: user.user,
                resource_type: "AWS::IAM::User",
            })
        })
    })
};

module.exports = IAMEnsureUnusedCredentialsAreDisabled;