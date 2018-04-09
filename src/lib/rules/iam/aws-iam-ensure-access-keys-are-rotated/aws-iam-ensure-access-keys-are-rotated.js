const co = require('co');
const Papa = require('papaparse');
const {NonCompliantResource, RuleResult} = require('../../../rule-result');

//------------------------------------------------------------------------------
// Rule Definition
//------------------------------------------------------------------------------

const IAMEnsureAccessKeysAreRotated = {};

IAMEnsureAccessKeysAreRotated.uuid = "b5dfcf10-f6a4-4eb0-acd6-439dfb813c1c";
IAMEnsureAccessKeysAreRotated.groupName = "IAM";
IAMEnsureAccessKeysAreRotated.tags = [["CIS", "1.1.0", "1.4"]];
IAMEnsureAccessKeysAreRotated.config_triggers = ["AWS::IAM::Group"];
IAMEnsureAccessKeysAreRotated.paths = {IAMEnsureAccessKeysAreRotated: "aws_iam_group"};
IAMEnsureAccessKeysAreRotated.docs = {
    description: 'All IAM access keys have been rotated in the last 90 days.',
    recommended: false
};
IAMEnsureAccessKeysAreRotated.schema = {type: 'number'};

IAMEnsureAccessKeysAreRotated.livecheck = co.wrap(function* (context) {
    const IAM = new context.provider.IAM();
    let {config, provider} = context;

    // Get credential report
    yield IAM.generateCredentialReport().promise();
    let report = yield IAM.getCredentialReport().promise();

    let content = report.Content.toString();
    let csv = Papa.parse(content, {header: true});
    let {data} = csv;

    let dateRange = config;

    function getDaysSince(date, dateSince = new Date()) {
        let XDaysAgoInMS = 86400000; //1 Day == 86,400,000 ms
        let differenceInMS = Math.abs(dateSince - date);
        return differenceInMS / XDaysAgoInMS;
    }

    function userAccessKeysAreValid(user) {
        let {
            access_key_1_active,
            access_key_1_last_used_date,
            access_key_1_last_rotated,
            access_key_2_active,
            access_key_2_last_used_date,
            access_key_2_last_rotated
        } = user;

        let isAccessKeyValid = (key_active, last_used, last_rotated) => {
            if (key_active === 'false')
                return true;
            else {
                if (getDaysSince(new Date(last_rotated)) > dateRange)
                    return false;
                if (new Date(last_rotated) > new Date(last_used)) //False if the last_used date was before the rotated date
                    return false;
            }
            return true;
        };

        return isAccessKeyValid(access_key_1_active, access_key_1_last_used_date, access_key_1_last_rotated) &&
            isAccessKeyValid(access_key_2_active, access_key_2_last_used_date, access_key_2_last_rotated);
    }

    let invalidAccessKeyUsers = data.filter(x => !userAccessKeysAreValid(x));

    if (invalidAccessKeyUsers.length > 0) {
        return new RuleResult({
            valid: 'fail',
            message: `${invalidAccessKeyUsers.length} users have an access key that has not been rotated in over ${dateRange} days, or has not been used since it was rotated.`,
            noncompliant_resources: invalidAccessKeyUsers.map(x => new NonCompliantResource({
                resource_id: x.user,
                resource_type: "AWS::IAM::User",
                message: `has an access key that has not been rotated in over ${dateRange} days, or has not been used since it was rotated.`
            }))
        })
    }
    else {
        return new RuleResult({valid: 'success'})
    }
});

module.exports = IAMEnsureAccessKeysAreRotated;