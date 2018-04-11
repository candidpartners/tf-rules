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
    });

    test("Each rule has a groupName", () => {
        _.forEach(rules,(rule,ruleName) => {
            expect(rule.groupName).toBeTruthy();
        })
    });

    test("Each rule config is an object, with a property of enabled", () => {
        let invalidRules = [];
        _.forEach(rules,(rule,ruleName) => {
            try{
                expect(rule.schema).toBeTruthy();
                expect(rule.schema.type).toBe("object");
                expect(rule.schema.properties.enabled).toBeTruthy();
                expect(rule.schema.properties.enabled.type).toBeTruthy();
            } catch(err){
                invalidRules.push(ruleName);
            }
        });

        if(invalidRules.length > 0)
            console.error(`The following rules don't have a proper schema ${JSON.stringify(invalidRules,null,2)}`);
        expect(invalidRules).toHaveLength(0);
    })
});