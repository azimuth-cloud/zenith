// Compares two strings independently of their case
const equalsIgnoreCase = (str1, str2) => str1.toLowerCase() == str2.toLowerCase();

// Gets the value of the given header from the given request
const getHeader = (req, header) => (
    req.rawHeadersIn
        .filter(h => equalsIgnoreCase(h[0], header))
        .map(h => h[1])
        .shift()
);

/**
 * Extracts an auth value from the request that will be used as the value of the
 * remote user/group header for upstream requests.
 *
 * There are three possible cases:
 *
 *   1. An SSL client certificate was verified by a downstream proxy server.
 *      In this case, the DN will be available in the "ssl-client-subject-dn"
 *      header, and the given field should be extracted and returned.
 *
 *   2. An "authorization" header is present, in which case the empty string should
 *      be returned to prevent the remote user/group header being added to the
 *      upstream request.
 *
 *   3. Neither the "ssl-client-subject-dn" or "authorization" headers are
 *      present, in which case the request should be treated as anonymous and
 *      the anonymous value should be returned.
 */
const getAuthFromRequest = (dnField, anonymousValue) => req => {
    const dn = getHeader(req, "ssl-client-subject-dn");
    if( dn ) {
        // If the processing of the DN fails, that means the DN does not have the correct format
        // In this case, return the empty string so that the request is treated as unauthenticated
        // rather than "authenticated as anonymous"
        try {
            return dn
                .split(",")
                .map(x => x.split("=", 2).map(y => y.trim()))
                .filter(x => equalsIgnoreCase(x[0], dnField))
                .map(x => x[1])
                .join(",");
        }
        catch(err) {
            return "";
        }
    }
    return getHeader(req, "authorization") ? "" : anonymousValue;
};

// Export functions for querying the user and groups
export default {
    user: getAuthFromRequest("CN", "system:anonymous"),
    groups: getAuthFromRequest("O", "system:unauthenticated")
}
