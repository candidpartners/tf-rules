const rules = require('./rules/index');
const _ = require('lodash');
const validator = require('validator');

describe("Rules", () => {
    test("Each rule has a uuid", () => {

        let noUUID = _.filter(rules, (rule,ruleName) => !rule.uuid);
        if(noUUID.length > 0){
            console.error(`The following do not have UUIDs ${noUUID.join('\n')}`)
        }

        let invalidUUID = _.filter(rules, (rule,ruleName) => validator.isUUID(rule.uuid) === false)
        if(invalidUUID.length > 0){
            console.error(`The following do not have valid UUIDs ${invalidUUID.join('\n')}`);
        }
        expect(noUUID).toHaveLength(0);
        expect(invalidUUID).toHaveLength(0);
    });

    test("Each rule uuid is unique", () => {
        let groupByUUID = _.groupBy(rules,r => r.uuid);

        _.forEach(groupByUUID, (rulesArray,uuid) => {
            //For better output
            expect({uuid,length:rulesArray.length, rulesArray}).toEqual({uuid,length:1,rulesArray})
        });
        expect(_.every(groupByUUID,(rules,uuid) => rules.length == 1)).toBeTruthy();
    })
});