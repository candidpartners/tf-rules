import React, {Component} from 'react';
import {Menu} from 'semantic-ui-react';
import {
    BrowserRouter as Router,
    Route,
    Link,
    Switch
} from 'react-router-dom';

import SideMenu from './side-menu';
import RulePage from './rule-page';

import './Main.css';
class App extends Component {

    render() {
        return (
            <div style={{display:"flex"}}>
                <SideMenu/>
                <Switch>
                    <Route path={"/rules/:ruleName"} component={RulePage}/>
                </Switch>
            </div>
        );
    }
}

export default App;
