const co = require('co');
const Papa = require('papaparse');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAM_AVOID_USE_OF_ROOT_ACCOUNT = {};

IAM_AVOID_USE_OF_ROOT_ACCOUNT.docs = {
    description: 'Checks that the root user has not logged in during the past X days.',
    recommended: false
};

IAM_AVOID_USE_OF_ROOT_ACCOUNT.config_triggers = ["AWS::IAM::User"];

IAM_AVOID_USE_OF_ROOT_ACCOUNT.tags = ["CIS"];

IAM_AVOID_USE_OF_ROOT_ACCOUNT.schema = {type: 'boolean'};

IAM_AVOID_USE_OF_ROOT_ACCOUNT.livecheck = co.wrap(function* (context, RequiredDaysSinceLastUsed) {
    const IAM = new context.provider.IAM();

    // Get credential report
    yield IAM.generateCredentialReport().promise();
    let report = yield IAM.getCredentialReport().promise();

    let content = report.Content.toString();
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    // Get root user
    let rootUser = data.find(x => x.user === `<root_account>`);
    let {password_last_used} = rootUser;

    function getNumberOfDaysSince(date) {
        return (new Date() - date.getTime()) / (1000 * 3600 * 24)
    }

    let loginDate = new Date(password_last_used);
    let daysSinceLastUsed = getNumberOfDaysSince(loginDate);

    if (daysSinceLastUsed >= RequiredDaysSinceLastUsed) {
        return {
            valid: 'success'
        };
    }
    else {
        return {
            valid: 'fail',
            message: `Requires <root_account> to not have logged in during the past ${RequiredDaysSinceLastUsed} days. <root_account> logged in ${daysSinceLastUsed.toFixed(2)} days ago.`
        }
    }
});

module.exports = IAM_AVOID_USE_OF_ROOT_ACCOUNT;

