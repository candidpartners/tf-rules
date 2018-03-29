const co = require('co');
const Papa = require('papaparse');
const _ = require('lodash');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAM_ENSURE_UNUSED_CREDENTIALS_ARE_DISABLED = {};

IAM_ENSURE_UNUSED_CREDENTIALS_ARE_DISABLED.docs = {
    description: 'Checks that the root user has not logged in during the past X days.',
    recommended: false
};

IAM_ENSURE_UNUSED_CREDENTIALS_ARE_DISABLED.tags = ["CIS"];

IAM_ENSURE_UNUSED_CREDENTIALS_ARE_DISABLED.schema = {type: 'boolean'};

IAM_ENSURE_UNUSED_CREDENTIALS_ARE_DISABLED.livecheck = co.wrap(function* (context, days) {
    const IAM = new context.provider.IAM();

    // Get credential report
    yield IAM.generateCredentialReport().promise();
    let report = yield IAM.getCredentialReport().promise();

    let content = report.Content.toString();
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    let dateRange = days;

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

module.exports = IAM_ENSURE_UNUSED_CREDENTIALS_ARE_DISABLED;