import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './Main';
import registerServiceWorker from './registerServiceWorker';
import {HashRouter} from 'react-router-dom';

const AppWrapper = (props) => (
    <HashRouter>
        <App/>
    </HashRouter>
);

ReactDOM.render(<AppWrapper />, document.getElementById('root'));
registerServiceWorker();
