const _ = require('lodash');
const AWS = require('aws-sdk');

module.exports = async function getProvider(providerConfig) {
    const targetConfig = {};
    if (providerConfig.region) {
        _.defaults(targetConfig, {region: providerConfig.region});
    }

    if (nconf.get('HTTPS_PROXY')) {
        const proxy = require('proxy-agent');
        const urlObject = url.parse(nconf.get('HTTPS_PROXY'));
        urlObject.auth = _.get(urlObject, 'auth', '').split(':').map(part => unescape(encodeURIComponent(part))).join(':');
        const encodedProxy = url.format(urlObject);
        debug('Using proxy of : %s', encodedProxy);
        targetConfig.httpOptions = {
            agent: proxy(encodedProxy)
        };
    }

    if (providerConfig.shared_credentials_file) {
        const fileContents = fs.readFileSync(providerConfig.shared_credentials_file, 'utf8');
        const iniConfig = iniParser.parse(fileContents);
        const profile = providerConfig.profile || 'default';
        if (iniConfig[profile]) {
            _.defaults(targetConfig, {
                credentials: {
                    accessKeyId: iniConfig[profile].aws_access_key_id,
                    secretAccessKey: iniConfig[profile].aws_secret_access_key,
                    sessionToken: iniConfig[profile].aws_session_token
                }
            });
        } else {
            console.log(colors.red('ERR!'), `provider.shared_credentials_file specified but [${profile}] profile not found`);
            process.exit(1);
        }
    } else if (providerConfig.assume_role) {
        debug('assumeRule configured: %O', providerConfig.assume_role);
        const sts = new AWS.STS(_.merge({}, {apiVersion: '2011-06-15'}, targetConfig));
        let params = {
            RoleArn: providerConfig.assume_role.role_arn,
            RoleSessionName: providerConfig.assume_role.session_name,
            DurationSeconds: 3600
        };
        if (_.get(providerConfig.assume_role, 'external_id')) {
            debug('external_id set : %s', providerConfig.assume_role.external_id);
            params.ExternalId = providerConfig.assume_role.external_id;
        }
        debug('assumeRule: %O', params);
        const result = await sts.assumeRole(params).promise();
        _.defaults(targetConfig, {
            credentials: {
                accessKeyId: result.Credentials.AccessKeyId,
                secretAccessKey: result.Credentials.SecretAccessKey,
                sessionToken: result.Credentials.SessionToken
            }
        });
    }

    AWS.config.update(targetConfig);
    return AWS;
}