require("luaerror");
if (not luaerror) then
	error("Please make sure you've installed gm_luaerror correctly")
end

local HTTP = HTTP;
local ipairs = ipairs;
local bit = bit;
local error = error;
local hook = hook;
local luaerror = luaerror;
local math = math;
local os = os;
local string = string;
local unpack = unpack;
local util = util;
-- debugging
local print = print;
local PrintTable = PrintTable;

module("sentry");

SDK_VALUE = {
	name = "GMSentry",
	version = "0.0.1",
}

local config = {
	endpoint = nil;
	privatekey = nil;
	publickey = nil;
	projectID = nil;
}

function UUID4()
	-- Copied from wirelib almost verbatim
	-- It would be easier to generate this by word rather than by byte, but
	-- MSVC's RAND_MAX = 0x7FFF, which means math.random(0, 0xFFFF) won't
	-- return all possible values.
	local bytes = {}
	for i = 1, 16 do bytes[i] = math.random(0, 0xFF) end
	bytes[7] = bit.bor(0x40, bit.band(bytes[7], 0x0F))
	bytes[9] = bit.bor(0x80, bit.band(bytes[7], 0x3F))
	return string.format("%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", unpack(bytes))
end

function ISODate(time)
	return os.date("!%Y-%m-%dT%H:%M:%S", time);
end

local function shouldReport()
	if (not config.endpoint) then
		return false;
	end
	-- Backoff logic goes here
	return true;
end

local function sentrifyStack(stack)
	local ret = {}
	for i, frame in ipairs(stack) do
		ret[i] = {
			filename = frame["source"],
			["function"] = frame["name"],
			module = frame["source"],
			lineno = frame["currentline"],
		}
	end
	return { frames = ret };
end

local SENTRY_HEADER_FORMAT = (
	"Sentry sentry_version=7, " ..
	"sentry_client=%s/%s, " ..
	"sentry_timestamp=%d, " ..
	"sentry_key=%s, " ..
	"sentry_secret=%s"
);
local function sentryAuthHeader(now)
	return SENTRY_HEADER_FORMAT:format(
		SDK_VALUE.name,
		SDK_VALUE.version,
		now,
		config.publickey,
		config.privatekey
	)
end

local function SendToServer(err, stacktrace)
	local now = os.time();
	local payload = {
		event_id = UUID4(),
		timestamp = ISODate(now),
		logger = "sentry",
		platform = "other",
		sdk = SDK_VALUE,
		exception = {{
			type = "error",
			value = err,
			stacktrace = sentrifyStack(stacktrace),
		}}
	};

	HTTP({
		url = config.endpoint,
		method = "POST",
		body = util.TableToJSON(payload),
		type = "application/json; charset=utf-8",
		headers = {
			["X-Sentry-Auth"] = sentryAuthHeader(now),
		},
		success = function(code, body, headers)
			print("Success!", code, body)
			PrintTable(headers)
		end,
		failed = function(reason)
			print("Failure", reason)
		end,
	})
end

local function OnLuaError(_, _, _, _, err, stack)
	if (not shouldReport()) then
		return;
	end
	SendToServer(err, stack)
	-- TODO
end

local function OnClientLuaError(ply, fallback, _, _, err, stack)
	if (not shouldReport()) then
		return;
	end
	-- TODO
end

local DSN_FORMAT = "^(https?://)(%w+):(%w+)@([%w.:]+)/(%w+)$";
local function parseDSN(dsn)
	local scheme, publickey, privatekey, host, project = string.match(dsn, DSN_FORMAT);
	if (not (scheme and publickey and privatekey and host and project)) then
		error("Malformed DSN!")
	end
	config.privatekey = privatekey;
	config.publickey = publickey;
	config.projectID = project;
	config.endpoint = scheme .. host .. "/api/" .. project .. "/store/";
end

function Setup(dsn, config)
	parseDSN(dsn)

	luaerror.EnableRuntimeDetour(true);
	luaerror.EnableCompiletimeDetour(true);
	luaerror.EnableClientDetour(true);

	hook.Add("LuaError", "Sentry Integration", OnLuaError);
	hook.Add("ClientLuaError", "Sentry Integration", OnClientLuaError);
end

function CaptureException(err)
	error("TODO")
end
