const co = require('co');
const Papa = require('papaparse');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMAvoidUseOfRootAccount = {};

IAMAvoidUseOfRootAccount.uuid = "5f11d82f-4435-4973-91e8-1175698f84b6";
IAMAvoidUseOfRootAccount.groupName = "IAM";
IAMAvoidUseOfRootAccount.config_triggers = ["AWS::IAM::User"];
IAMAvoidUseOfRootAccount.paths = {IAMAvoidUseOfRootAccount: "aws_iam_user"};
IAMAvoidUseOfRootAccount.docs = {
    description: 'The root account has not logged in in the required number of days.',
    recommended: false
};
IAMAvoidUseOfRootAccount.schema = {type: 'boolean'};


IAMAvoidUseOfRootAccount.livecheck = co.wrap(function* (context, RequiredDaysSinceLastUsed) {
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

module.exports = IAMAvoidUseOfRootAccount;

