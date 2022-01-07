const getCookie = name => {
    const processedName = `${name}=`;

    const decodedCookie = decodeURIComponent(document.cookie);

    const cookies = decodedCookie.split(';');

    for (const item of cookies) {
        const cookie = item.trim();

        if (cookie.indexOf(processedName) === 0) {
            return cookie.substring(processedName.length, cookie.length);
        }
    }
};

const fetchAccessToken = () => {
    const accessToken = getCookie("access_token");
    return accessToken ? decodeURI(accessToken) : accessToken;
}

const isAuthenticate = () => {
  const accessToken = fetchAccessToken();

  return !!accessToken;
}

module.exports = { fetchAccessToken, isAuthenticate }
