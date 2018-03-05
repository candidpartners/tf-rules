import React from 'react';
import {withRouter} from 'react-router-dom';
import rules from './lib/rules.json'
import {Segment} from 'semantic-ui-react';

class RulePage extends React.Component {

    getRule(ruleName) {
        return rules.find(x => x.name === ruleName);
    }

    render() {
        let {ruleName} = this.props.match.params;
        let rule = this.getRule(ruleName);
        return (
            <div>
                {!rule && (
                    <div>No rule found!</div>
                )}
                {rule && (
                    <div style={{padding:"10px"}}>
                        <Segment>
                            <h1 style={{marginBottom:"0"}}>{rule.name}</h1>
                            <p style={{color:"#aaaaaa"}}>{rule.uuid}</p>

                            <h4>Description</h4>
                            <p>{rule.docs.description}</p>
                            <p>Recommended: {rule.docs.recommended ?  : false}</p>
                        </Segment>

                        {JSON.stringify(rule)}
                    </div>
                )}
            </div>
        )
    }
}

export default withRouter(RulePage);