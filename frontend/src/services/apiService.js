const {fetchAccessToken} = require("@/services/authenticationService");

const validate = res => res.ok ? Promise.resolve(res) : Promise.reject(res);

const fetchAvailableAuths = () =>
    fetch("./available-auths")
        .then(validate)
        .then(response => response.json());

const fetchCctrayJson = () => {
  return fetch("./v1/cctray", {headers: new Headers({"Authorization": fetchAccessToken()})})
      .then(validate)
      .then((res) => res.json());
}

const authenticate = (username, password) => {
  return fetch("./login/basic",
      {
        method: 'POST',
        headers: new Headers({"Content-Type": "application/json"}),
        body: JSON.stringify({username, password})
      }
  )
      .then(validate);
}

module.exports = { fetchAvailableAuths, fetchCctrayJson, authenticate }
