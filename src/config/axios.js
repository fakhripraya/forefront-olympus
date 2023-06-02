const axios = require('axios');

var cancelSourceToken = () => {
    return axios.CancelToken.source();
}

const Axios = (baseUrl) => {
    return axios.create({
        baseURL: baseUrl,
        timeout: 61000,
        withCredentials: true,
    });
}

module.exports = {
    Axios,
    cancelSourceToken
}