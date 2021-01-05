function envoy_on_request(request_handle)
    local headers = request_handle:headers()
    local metadata = request_handle:metadata()

    local host = headers:get(":authority")
    if host == nil then return end

    local domain = "%s"
    if host ~= domain then request_handle:respond({[":status"] = "421"}, "") end
end

function envoy_on_response(response_handle) end
