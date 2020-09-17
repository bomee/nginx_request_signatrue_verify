local secret_table = {
    v1 = "secret_v1",
    v2 = "secret_v2"
}

local STATUS_PRECONDITION_REQUIRED = 428


if ngx.var.query_string == nil then
    ngx.log(ngx.WARN, "Required parameter missing.")
    ngx.status = STATUS_PRECONDITION_REQUIRED
    ngx.say("Required parameter missing.")
    ngx.exit(STATUS_PRECONDITION_REQUIRED)
    return
end

local function safe_str(value)
    if value == nil then 
        return 'nil'
    else 
        return value
    end
end

-- parse query_string
local query_table = {}
local ts = nil
local sign = nil
local sign_v = nil
local qt_idx = 1
for str in string.gmatch(ngx.var.query_string, "([^&]+)&?") do 
    if string.find(str, "ts=") then
        ts = string.gsub(str, "ts=", "", 1)
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

if sign == nil or ts == nil or sign_v == nil then
    local out = "Required parameter missing: sign=" .. safe_str(sign_v) .. 
                ", ts=" .. safe_str(ts) .. 
                ", sign_v=" .. safe_str(sign_v)
    ngx.log(ngx.WARN, out)
    ngx.status = STATUS_PRECONDITION_REQUIRED
    ngx.say(out)
    ngx.exit(STATUS_PRECONDITION_REQUIRED)
    return
end

-- Timestamp difference check
local  = tonumber(ts)
if (os.time() - tonumber(ts)) > 5 * 60 then
    ngx.log(ngx.WARN, "The time difference should not be more than 5 minutes")
    ngx.status = STATUS_PRECONDITION_REQUIRED
    ngx.say("The time difference should not be more than 5 minutes")
    ngx.exit(STATUS_PRECONDITION_REQUIRED)
end

table.sort(query_table)

-- md5 body
if ngx.var.http_content_type ~= nil and (string.find(ngx.var.http_content_type, 'json') or
    string.find(ngx.var.http_content_type, 'www-form-urlencoded'))
then
    ngx.req.read_body()
    local req_body = ngx.req.get_body_data()
    local body_md5 = ngx.md5(req_body)
end

local secret = secret_table[sign_v]

if secret == nil then
    ngx.log(ngx.WARN, "Unsupported signature version: " .. sign_v);
    ngx.status = STATUS_PRECONDITION_REQUIRED
    ngx.say("Unsupported signature version: " .. sign_v)
    ngx.exit(STATUS_PRECONDITION_REQUIRED)
    return
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
    ngx.status = STATUS_PRECONDITION_REQUIRED
    ngx.say("Illegal signature: "..sign_str)
    ngx.exit(STATUS_PRECONDITION_REQUIRED)
    return
end
