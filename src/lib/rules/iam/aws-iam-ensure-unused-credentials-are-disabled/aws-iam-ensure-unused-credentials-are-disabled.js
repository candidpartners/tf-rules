const co = require('co');
const Papa = require('papaparse');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMEnsureUnusedCredentialsAreDisabled = {};

IAMEnsureUnusedCredentialsAreDisabled.uuid = "944996af-32cd-4af6-9bb2-03819a631b44";
IAMEnsureUnusedCredentialsAreDisabled.groupName = "IAM";
IAMEnsureUnusedCredentialsAreDisabled.tags = ["CIS | 1.1.0 | 1.3"];
IAMEnsureUnusedCredentialsAreDisabled.config_triggers = ["AWS::IAM::User"];
IAMEnsureUnusedCredentialsAreDisabled.paths = {IAMEnsureUnusedCredentialsAreDisabled: "aws_iam_user"};
IAMEnsureUnusedCredentialsAreDisabled.docs = {
    description: 'Credentials unused for at least 90 days are disabled.',
    recommended: false
};
IAMEnsureUnusedCredentialsAreDisabled.schema = {type: 'number'};


IAMEnsureUnusedCredentialsAreDisabled.livecheck = co.wrap(function* (context) {
    let {config, provider} = context;
    const IAM = new context.provider.IAM();

    // Get credential report
    yield IAM.generateCredentialReport().promise();
    let report = yield IAM.getCredentialReport().promise();

    let content = report.Content.toString();
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    let dateRange = config;

    function getDaysAgo(date) {
        let currentDate = new Date();
        let XDaysAgoInMS = 86400000; //1 Day == 86,400,000 ms
        let differenceInMS = Math.abs(date - currentDate);
        return differenceInMS/XDaysAgoInMS;
    }

    function userIsValid(user) {
        let {password_enabled, password_last_used} = user;
        if (password_enabled !== 'true')
            return true;
        else
            return getDaysAgo(new Date(password_last_used)) < dateRange;
    }

    function userAccessKeysAreValid(user){
        let {
            access_key_1_active,
            access_key_1_last_used_date,
            access_key_2_active,
            access_key_2_last_used_date
        } = user;

        let isAccessKeyValid = (key_active,last_used) => key_active === 'false' || getDaysAgo(last_used) < dateRange;

        return isAccessKeyValid(access_key_1_active,access_key_1_last_used_date) &&
                isAccessKeyValid(access_key_2_active, access_key_2_last_used_date);
    }

    let invalidPasswordUsers = data.filter(x => !userIsValid(x));
    let invalidAccessKeyUsers = data.filter(x => !userAccessKeysAreValid(x));

    if(invalidPasswordUsers.length > 0 || invalidAccessKeyUsers > 0){
        return {
            valid: 'fail',
            message: `${invalidPasswordUsers.length} users have a password they have not used in ${dateRange} days. ${invalidAccessKeyUsers.length} users have an access key they have not used in ${dateRange} days.`
        }
    }
    else{
        return { valid: 'success' }
    }
});

module.exports = IAMEnsureUnusedCredentialsAreDisabled;