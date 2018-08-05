require("luaerror");
if (not luaerror) then
	error("Please make sure you've installed gm_luaerror correctly")
end

local HTTP = HTTP;
local ServerLog = ServerLog;
local SysTime = SysTime;
local bit = bit;
local error = error;
local hook = hook;
local ipairs = ipairs;
local luaerror = luaerror;
local math = math;
local os = os;
local pairs = pairs;
local string = string;
local table = table;
local tonumber = tonumber;
local tostring = tostring;
local type = type;
local unpack = unpack;
local util = util;
local xpcall = xpcall;
-- debugging
local debug = debug
local print = print;
local PrintTable = PrintTable;

local g = _G;

module("sentry");

--
--    Global Config
--
local config = {
	endpoint = nil;
	privatekey = nil;
	publickey = nil;
	projectID = nil;
}

--
--    Versioning
--
SDK_VALUE = {
	name = "GMSentry",
	version = "0.0.1",
}
-- LuaJIT Style
Version = string.format("%s %s", SDK_VALUE.name, SDK_VALUE.version);
VersionNum = string.format("%02d%02d%02d", string.match(SDK_VALUE.version, "(%d+).(%d+).(%d+)"))


--
--    Utility Functions
--
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

function WriteLog(message, ...)
	ServerLog(string.format("Sentry: %s\n", message:format(...)));
end


--
--    Module Detection
--
DetectedModules = {};
DetectionFuncs = {
	mysqloo = function(mysqloo)
		return string.format("%d.%d", mysqloo.VERSION, mysqloo.MINOR_VERSION);
	end;
	CPPI = function(CPPI)
		local name = CPPI:GetName();
		local version = CPPI:GetVersion();
		if (version == CPPI.CPPI_NOT_IMPLEMENTED) then
			-- ???
			return nil;
		end
		return version, name;
	end;
	ulx = function(ulx)
		-- Why is this better than ulx.version
		local ULib = g["ULib"];
		if (ULib and ULib.pluginVersionStr) then
			return ULib.pluginVersionStr("ULX");
		end
		return ulx.version or ulx.VERSION;
	end;
	ULib = function(ULib)
		if (ULib.pluginVersionStr) then
			return ULib.pluginVersionStr("ULib");
		end
		return ULib.version or ULib.VERSION;
	end;
	GM = function(GM)
		if (not GM.Version) then
			return nil;
		end
		return GM.Version, string.format("Gamemode: %s", GM.Name);
	end;
	_G = function(_G)
		return _G["VERSION"], "Garry's Mod";
	end
}
DetectionFuncs["GAMEMODE"] = DetectionFuncs["GM"];

local LUAJIT_VERSION = "(.+) (%d+%.%d+%.%d+)";
local function detectModules()
	local VERSION = g["VERSION"];

	for name, value in pairs(g) do
		local func = DetectionFuncs[name];
		if (func) then
			-- Overrides
			local _, version, override = xpcall(func, CaptureException, value);

			if (version) then
				DetectedModules[override or name] = tostring(version);
			end
		elseif (type(value) == "table" and name ~= "sentry") then
			-- Magic guessing game
			local version = value["version"] or value["Version"] or value["VERSION"];

			if (version and version ~= VERSION and type(version) ~= "function") then
				version = tostring(version);

				-- Try and deal with LuaJIT style version strings
				local override, realversion = string.match(version, LUAJIT_VERSION);
				if (override) then
					version = realversion
				end

				DetectedModules[override or name] = version;
			end
		end
	end
end


--
--    Rate Limiting
--
local retryAfter = nil;
local function shouldReport()
	if (not config.endpoint) then
		return false;
	elseif (retryAfter ~= nil) then
		local now = SysTime();
		if (retryAfter > now) then
			return false;
		end

		retryAfter = nil;
	end
	-- Backoff logic goes here
	return true;
end

local function doBackoff(backoff)
	local expires = SysTime() + backoff;
	if (retryAfter == nil or retryAfter < expires) then
		WriteLog("Rate Limiting for %d seconds!", backoff);
		retryAfter = expires;
	end
end

local function detectRateLimiting(code, headers)
	local backoff = tonumber(headers["Retry-After"]);
	-- Shouldn't happen, but might
	if (code == 429 and not backoff) then
		backoff = 20;
	end

	if (not backoff) then
		return false;
	end

	doBackoff(backoff);

	return true;
end


--
--    File Identification
--
local ADDON_FILE_PATTERN = "^@addons/([^/]+)/lua/(.*).lua$"
local GAMEMODE_FILE_PATTERN = "^@gamemodes/([^/]+)/(.*).lua$"
local OTHER_FILE_PATTERN = "^@lua/(.*).lua$"
local function modulify(path)
	if (path == "=[C]") then
		return "engine";
	elseif (path == "@lua_run") then
		return "lua_run";
	end

	local addon, rest = string.match(path, ADDON_FILE_PATTERN);
	if (addon) then
		return addon .. "." .. rest:gsub("/", ".");
	end

	local gamemode, rest = string.match(path, GAMEMODE_FILE_PATTERN);
	if (gamemode) then
		return gamemode .. "." .. rest:gsub("/", ".");
	end

	local rest = string.match(path, OTHER_FILE_PATTERN);
	if (rest) then
		return "unknown." .. rest:gsub("/", ".")
	end

	return "unknown";
end


--
--    Stack Reverse Engineering
--
local function sentrifyStack(stack)
	-- Sentry likes stacks in the oposite order to lua
	stack = table.Reverse(stack);

	-- The first entry from LuaError is sometimes useless
	if (stack[#stack]["source"] == "=[C]" and stack[#stack]["name"] == "") then
		table.remove(stack);
	end
	-- If someone has called `error`, remove it from the stack trace
	if (stack[#stack]["source"] == "=[C]" and stack[#stack]["name"] == "error" ) then
		table.remove(stack);
	end

	local ret = {}
	for i, frame in ipairs(stack) do
		ret[i] = {
			filename = frame["source"]:sub(2),
			["function"] = frame["name"] or "<unknown>",
			module = modulify(frame["source"]),
			lineno = frame["currentline"],
		}
	end
	return { frames = ret };
end

local function getStack()
	local level = 3; -- 1 = this, 2 = CaptureException

	local stack = {};
	while true do
		local info = debug.getinfo(level, "Sln");
		if (not info) then
			break;
		end

		stack[level - 2] = info;

		level = level + 1;
	end

	return stack;
end

local function stripFileData(err, stack)
	local match, file, line = string.match(err, "^((.+%.lua):(%d+): ).+$");
	if (not match) then
		return err;
	end

	for _, frame in pairs(stack) do
		if (frame["source"] == "@" .. file and tostring(frame["currentline"]) == tostring(line)) then
			err = err:sub(#match + 1);
			break;
		end
	end

	return err;
end


--
--    Actual HTTP Integration
--
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
		}},
		modules = DetectedModules,
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
			local result = util.JSONToTable(body) or {};

			if (detectRateLimiting(code, headers)) then
				return;
			elseif (code ~= 200) then
				if (code >= 500) then
					WriteLog("Server is offline, trying later");
					doBackoff(2);
					return
				elseif (code == 401) then
					WriteLog("Access denied: %s", result["error"]);
					-- If sentry tells us to go away, go away properly
					config.endpoint = nil;
					return;
				else
					WriteLog("Got HTTP %d from the server: %s", code, result["error"] or body)
					return;
				end
			end

			-- Debugging
			print("Success! Event stored with ID " .. (result["id"] or "?"))
		end,
		failed = function(reason)
			-- This is effectively useless
			WriteLog("HTTP request failed: %s", reason);
		end,
	})
end


--
--    Reporting Functions
--
local function OnLuaError(is_runtime, _, file, lineno, err, stack)
	if (not shouldReport()) then
		return;
	end

	if (#stack == 0) then
		stack[1] = {
			name = is_runtime and "<unknown>" or "<compile>",
			source = '@' .. file,
			currentline = lineno,
		}
	end


	SendToServer(err, stack)
	-- TODO
end

function CaptureException(err)
	local stack = getStack();
	err = stripFileData(err, stack);

	SendToServer(err, stack)
end


--
-- Initial Configuration
--
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

	hook.Add("LuaError", "Sentry Integration", OnLuaError);

	-- Once the server has initialised, get all the things with a "version" field
	hook.Add("Initialize", "Sentry Integration", detectModules)
	-- Just in case we're being called in the Initialize hook, also get them now.
	detectModules();
end
