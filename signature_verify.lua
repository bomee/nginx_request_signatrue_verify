local ngx_log = ngx.log
local ngx_WARN = ngx.WARN
local _M  = {}

function _M.exec(secret_table, prevent)
    local HTTP_PRECONDITION_FAILED = 412

    local function verify_fail(message)
        ngx_log(ngx_WARN, message)
        if prevent then
            ngx.status = HTTP_PRECONDITION_FAILED
            ngx.say(message)
            ngx.exit(HTTP_PRECONDITION_FAILED)
        end
        return
    end

    if ngx.var.query_string == nil then
        return verify_fail("Required parameter missing.")
    end

    local function safe_str(value)
        if value == nil then
            return ''
        else
            return tostring(value)
        end
    end

    local uri_args = ngx.req.get_uri_args()
    local sign_ts = uri_args['sign_ts']
    local sign = uri_args['sign']
    local sign_v = uri_args['sign_v']

    if sign == nil or sign_ts == nil or sign_v == nil then
        return verify_fail(
            "Required parameter missing: sign=" .. safe_str(sign) ..
            ", sign_ts=" .. safe_str(sign_ts) ..
            ", sign_v=" .. safe_str(sign_v)
        )
    end

    -- Timestamp difference check
    if (os.time() - tonumber(sign_ts)) > 5 * 60 then
        return verify_fail("The time difference should not be more than 5 minutes")
    end

    local function fetch_request_body()
        ngx.req.read_body()
        local body = ngx.req.get_body_data()

        if not body then
        -- request body might've been written to tmp file if body > client_body_buffer_size
        local file_name = ngx.req.get_body_file()
        local file = io.open(file_name, "rb")

        if not file then
            return nil
        end

        body = file:read("*all")
        file:close()
        end
        return body
    end

    local secret = secret_table[sign_v]

    if secret == nil then
        return verify_fail("Unsupported signature version: " .. sign_v)
    end

    -- Signature algorithm：base64(hmac_sha1(secrect, method + uri + sort(query) + md5(body)))
    -- Query name and value must use encodeURIComponent
    local sign_str = ngx.var.request_method .. ngx.var.uri

    local uri_args_keys = {}
    for key, _ in pairs(uri_args) do
        if key ~= "sign" then
            table.insert(uri_args_keys, key)
        end
    end
    table.sort(uri_args_keys)
    for _, key in ipairs(uri_args_keys) do
        sign_str = sign_str .. key .. "=" .. safe_str(uri_args[key])
    end

    -- Md5 Body
    if ngx.var.http_content_type ~= nil
        and ngx.var.http_content_length ~= nil
        and tonumber(ngx.var.http_content_length) > 0
        and (string.find(ngx.var.http_content_type, 'json') or string.find(ngx.var.http_content_type, 'www-form-urlencoded')) then
        sign_str = sign_str .. ngx.md5(fetch_request_body())
    end

    local sign_by_server = ngx.encode_base64(ngx.hmac_sha1(secret, sign_str))
    if sign_by_server ~= sign then
        ngx_log(ngx_WARN, "Signature verify failure: sign_str=" .. sign_str.. ", client_sign=" .. sign .. ", server_sign=" .. sign_by_server);
        return verify_fail("Illegal signature")
    end
end

return _M
