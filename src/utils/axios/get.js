const axios = require('axios');
const { Axios, cancelSourceToken } = require('../../config/axios');
const { GET } = require('../../variables/general');

const GETRequest = async (config) => {
    // init result
    var result = { httpResponse: null, httpCode: null, error: false, errContent: null };
    // creates the cancel token source
    var cancelSource = cancelSourceToken();
    // Start timing now
    console.time(config.logTitle);

    await Axios(config.endpoint)({
        method: GET,
        url: config.url,
        headers: config.headers,
        cancelToken: cancelSource.token
    }).then(res => {
        result.response = res.data;
        result.httpCode = res.status;
    }).catch(err => {
        if (err.response) {
            if (axios.isCancel(err)) cancelSource.cancel();
            result.error = true;
            result.errContent = err.response.data;
            result.httpCode = err.response.status;
        } else result.httpCode = 500;
    });

    // End timing now
    console.timeEnd(config.logTitle);

    return result;
};

module.exports = {
    GETRequest
}