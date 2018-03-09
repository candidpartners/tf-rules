import React from 'react';
import {withRouter} from 'react-router-dom';
import rules from './lib/rules.json'
import {Segment, Menu, Label} from 'semantic-ui-react';
import Form from 'react-jsonschema-form';
const YAML = require('json2yaml');

class RulePage extends React.Component {

    constructor(props) {
        super(props)

        this.state = {
            activeItem: "Schema",
            generatedYaml: ""
        }
    }

    getRule(ruleName) {
        return rules.find(x => x.name === ruleName);
    }

    generateYaml(rule, data) {
        console.log(data)
        this.setState({generatedYaml: `${rule.name} : 
  ${YAML.stringify(data)}`})
    }

    render() {
        let {ruleName} = this.props.match.params;
        let rule = this.getRule(ruleName);
        return (
            <div style={{width: '100%'}}>
                {!rule && (
                    <div>No rule found!</div>
                )}
                {rule && (
                    <div style={{padding: "10px", height: 720, overflowY: 'scroll'}}>
                        <Segment>
                            <h1 style={{marginBottom: "0"}}>{rule.name}</h1>
                            <p style={{color: "#aaaaaa"}}>{rule.uuid}</p>

                            {rule.docs.recommended && (
                                <Label color={"yellow"} content={"Recommended"}
                                       style={{marginLeft: 0, marginBottom: 20}}/>
                            )}

                            <p>{rule.docs.description}</p>
                        </Segment>

                        <Menu pointing>
                            {["Schema", "JSON", "Generate Config"].map(x => (
                                <Menu.Item key={x} name={x} active={this.state.activeItem === x}
                                           onClick={() => this.setState({activeItem: x})}/>
                            ))}
                        </Menu>

                        {this.state.generatedYaml && (
                            <pre>{this.state.generatedYaml}</pre>
                        )}

                        {this.state.activeItem == "Schema" && (
                            <Segment style={{overflowX: 'auto'}}>
                                <pre>
                                    {JSON.stringify(rule.schema, null, 2)}
                                </pre>
                            </Segment>
                        )}

                        {this.state.activeItem == "JSON" && (
                            <Segment style={{overflowX: 'auto'}}>
                                <pre>
                                    {JSON.stringify(rule, null, 2)}
                                </pre>
                            </Segment>
                        )}

                        {this.state.activeItem == "Generate Config" && (
                            <Segment>
                                {rule.schema.anyOf && (
                                    rule.schema.anyOf.map(x => (
                                        <Form
                                            schema={x}
                                            onSubmit={(result) => this.generateYaml(rule, result.formData)}
                                        />
                                    ))
                                )}
                                <Form
                                    schema={rule.schema}
                                    onSubmit={(result) => this.generateYaml(rule, result.formData)}
                                />
                            </Segment>
                        )}

                    </div>
                )}
            </div>
        )
    }
}

export default withRouter(RulePage);