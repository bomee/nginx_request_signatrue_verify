local secret_table = {
    v1 = "R2$ty@keWUwWj7fVDj@&VUgsCkAGF6yy",
    v2 = "&E00bAS%9QYH@yHI^E8s*@mo6WvxZ7Zk",
    v3 = "o@ZR&x7rE5T%&bJ$iZA51Db257BDfht1",
    v4 = "TKjO$04u7gQw$D%PrpYz4LeFWe&LUx&s",
    v5 = "OXO11FdNJ0Pgo1%8mOBtGm3DN!*ipdo0"
}

local STATUS_PRECONDITION_FAILED = 412

local function verify_fail(message)
    ngx.log(ngx.WARN, message)
    -- ngx.status = STATUS_PRECONDITION_FAILED
    -- ngx.say(message)
    -- ngx.exit(STATUS_PRECONDITION_FAILED)
    return
end

if ngx.var.query_string == nil then
    return verify_fail("Required parameter missing.")
end

local function safe_str(value)
    if value == nil then 
        return 'nil'
    else 
        return value
    end
end

-- Parse query_string to table for sort
local query_table = {}
local sign_ts = nil
local sign = nil
local sign_v = nil
local qt_idx = 1
for str in string.gmatch(ngx.var.query_string, "([^&]+)&?") do 
    if string.find(str, "sign_ts=") then
        sign_ts = string.gsub(str, "sign_ts=", "", 1)
    elseif string.find(str, "sign=") then
        sign = string.gsub(str, "sign=", "", 1)
        goto next
    elseif string.find(str, "sign_v=") then
        sign_v = string.gsub(str, "sign_v=", "", 1)
    end
    query_table[qt_idx] = str
    qt_idx = qt_idx + 1
    ::next::
end

if sign == nil or sign_ts == nil or sign_v == nil then
    return verify_fail(out) 
end

-- Timestamp difference check
if (os.time() - tonumber(sign_ts)) > 5 * 60 then
    return verify_fail("The time difference should not be more than 5 minutes")
end

table.sort(query_table)

-- Md5 body
if ngx.var.http_content_type ~= nil and (string.find(ngx.var.http_content_type, 'json') or string.find(ngx.var.http_content_type, 'www-form-urlencoded')) then
    ngx.req.read_body()
    local req_body = ngx.req.get_body_data()
    local body_md5 = ngx.md5(req_body)
end

local secret = secret_table[sign_v]

if secret == nil then
    return verify_fail("Unsupported signature version: " .. sign_v)
end

-- Signature algorithm：base64(hmac_sha1(secrect, uri + sort(query_string) + md5(body)))
local sign_str = ngx.var.uri

for k, v in ipairs(query_table) do
    sign_str = sign_str .. v
end

if body_md5 ~= nil then
    sign_str = sign_str .. body_md5
end

local sign_by_server = ngx.encode_base64(ngx.hmac_sha1(secret, sign_str))
if sign_by_server ~= sign then
    ngx.log(ngx.WARN, "Signature verify failure: sign_str=" .. sign_str.. ", client_sign=" .. sign .. ", server_sign=" .. sign_by_server);
    return verify_fail("Illegal signature")
end
