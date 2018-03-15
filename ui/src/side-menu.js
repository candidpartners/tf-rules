import React from 'react';
import {Menu} from 'semantic-ui-react';
import {
    BrowserRouter as Router,
    Route,
    Link
} from 'react-router-dom';
import _ from 'lodash';
import rules from './lib/rules.json';

let rulesByGroup = _.groupBy(rules,r => r.groupName);

const SideMenu = ({}) => (
    <Menu vertical style={{height:"100vh",overflowY:"scroll", minWidth:"300px"}}>
        <Menu.Item>
            <Link to={`/`}>
                <h2>Snitch</h2>
            </Link>
        </Menu.Item>
        {_.map(rulesByGroup, (value, key) => (
            <Menu.Item key={key}>
                <Menu.Header>{key}</Menu.Header>

                <Menu.Menu>
                    {_.map(value,rule => (
                        <Link key={rule.name} to={`/rules/${rule.name}`}>
                            <Menu.Item>{rule.name}</Menu.Item>
                        </Link>
                    ))}
                </Menu.Menu>
            </Menu.Item>
        ))}
    </Menu>
);

export default SideMenu;