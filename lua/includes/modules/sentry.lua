require("luaerror");
if (not luaerror) then
	error("Please make sure you've installed gm_luaerror correctly")
end

local GetHostName = GetHostName;
local HTTP = HTTP;
local IsValid = IsValid;
local ServerLog = ServerLog;
local SysTime = SysTime;
local bit = bit;
local error = error;
local hook = hook;
local ipairs = ipairs;
local isstring = isstring;
local luaerror = luaerror;
local math = math;
local net = net;
local os = os;
local pairs = pairs;
local setmetatable = setmetatable;
local string = string;
local system = system;
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
	endpoint = nil,
	privatekey = nil,
	publickey = nil,
	projectID = nil,
	tags = {},
	release = nil,
	environment = nil,
	server_name = nil,
	no_detour = {},
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

function GetOSName()
	if (system.IsWindows()) then
		return "Windows";
	elseif (system.IsOSX()) then
		return "macOS";
	elseif (system.IsLinux()) then
		return "Linux";
	end
	return nil;
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
		return string.format("%d.%d", mysqloo.VERSION, mysqloo.MINOR_VERSION or 0);
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
local skipNext = nil;
local function shouldReport(err)
	if (not config.endpoint) then
		return false;
	elseif (retryAfter ~= nil) then
		local now = SysTime();
		if (retryAfter > now) then
			return false;
		end

		retryAfter = nil;
	end

	if (skipNext == err) then
		skipNext = nil;
		return false;
	end
	skipNext = nil;

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
local ADDON_GAMEMODE_FILE_PATTERN = "^@addons/[^/]+/gamemodes/([^/]+)/(.*).lua$"
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
	if (not gamemode) then
		gamemode, rest = string.match(path, ADDON_GAMEMODE_FILE_PATTERN);
	end
	if (gamemode) then
		return gamemode .. "." .. rest:gsub("/", ".");
	end

	local rest = string.match(path, OTHER_FILE_PATTERN);
	if (not rest) then
		return "unknown";
	end

	local name, id = luaerror.FindWorkshopAddonFileOwner(path:sub(2))
	if (not name) then
		return "unknown." .. rest:gsub("/", ".")
	end

	-- Asciify name
	name = name:lower():gsub("[^%w]+", "-"):gsub("%-+", "-"):gsub("^%-*(.-)%-*$", "%1");
	-- Lua doesn't do unicode, so if the workshop name is in cyrilic or something, it'll now be empty
	if (name:len() < 3) then
		-- Heck
		name = "workshop-" .. id;
	end

	return name .. "." .. rest:gsub("/", ".")
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
	local match, file, line = string.match(err, "^((.+):(%d+): ).+$");
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

local ADDON_BLAME_PATTERN = "^addons/([^/]+)/";
local GAMEMODE_BLAME_PATTERN = "^gamemodes/([^/]+)/";
local function calculateBlame(stack)
	for _, frame in pairs(stack) do
		if (frame["source"] ~= "=[C]") then
			local source = frame["source"]:sub(2);

			local wsname, wsid = luaerror.FindWorkshopAddonFileOwner(source);
			if (wsname) then
				return {
					{ "addon", "workshop-" .. wsid },
					{ "addon-name", wsname },
				}
			end

			local addon = string.match(source, ADDON_BLAME_PATTERN);
			if (addon) then
				return {
					{ "addon", addon },
				}
			end

			local gamemode = string.match(source, GAMEMODE_BLAME_PATTERN);
			if (gamemode) then
				return {
					{ "gamemode", gamemode },
				}
			end
		end
	end

	return {};
end


--
--    Transaction Management
--
local transactionStack = {}
function IsInTransaction()
	return #transactionStack > 0;
end

local function pushTransaction(data)
	local txn = {
		data = data,
		ctx = {},
		id = UUID4(),
	}

	transactionStack[#transactionStack + 1] = txn;

	return txn.id;
end

local function popTransaction(id)
	for i, txn in pairs(transactionStack) do
		if (txn.id == id) then
			-- Nuke everything above this tranasction in the stack
			while transactionStack[i] do
				table.remove(transactionStack, i);
			end

			-- If this is the last transaction, discard any pending skips
			-- "Bug": If you start a transaction from within builtin xpcall inside an
			-- active transaction, that transaction fails and you immediately call that
			-- transaction again and it fails again, the second error won't be reported
			-- to sentry.
			-- If you run into this bug, reevaulate your life choices
			if (not IsInTransaction()) then
				skipNext = nil;
			end

			return txn.data;
		end
	end

	error("Unknown Transaction '".. tostring(id) .. "'!");
end

local function getTransactionData()
	local res = {}

	for _, txn in ipairs(transactionStack) do
		table.Merge(res, txn.data);
		table.Merge(res, txn.ctx);
	end

	return res;
end

local function getCurrentTransaction()
	return transactionStack[#transactionStack];
end


--
--    Context Management
--
local function getUserContext(extra)
	local ply = extra["user"]
	if (not IsValid(ply)) then
		return nil;
	end

	return {
		id = ply:SteamID(),
		username = ply:Nick(),
		ip = ply:IPAddress(),
		steamid64 = ply:SteamID64(),
	}
end

local function getContexts(extra)
	return {
		os = {
			name = GetOSName(),
		},
		runtime = {
			name = "Garry's Mod",
			version = g["VERSIONSTR"],
		},
		app = {
			app_start_time = math.floor(os.time() - SysTime()),
		},
		user = getUserContext(extra),
	}
end

local function getTags(extra)
	local tags = {};

	for name, value in pairs(config.tags) do
		table.insert(tags, {name, value});
	end

	-- These _suppliment_ rather than replace sdk tags
	if (extra["tags"]) then
		for name, value in pairs(extra.tags) do
			table.insert(tags, {name, value});
		end
	end

	return tags
end


--
--    Payload
--
local function buildPayload(err, stacktrace, extra)
	local txn = getTransactionData();
	table.Merge(txn, extra)

	local tags = getTags(txn);
	table.Add(tags, calculateBlame(stacktrace));

	return {
		event_id = UUID4(),
		timestamp = ISODate(os.time()),
		logger = "sentry",
		platform = "other",
		sdk = SDK_VALUE,
		exception = {{
			type = "error",
			value = err,
			stacktrace = sentrifyStack(stacktrace),
		}},
		modules = DetectedModules,
		contexts = getContexts(txn),
		tags = tags,
		environment = config["environment"],
		release = config["release"],
		server_name = config["server_name"],
		level = txn["level"],
		extra = txn["extra"],
		culprit = txn["culprit"],
	};
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
		os.time(),
		config.publickey,
		config.privatekey
	)
end

local function SendToServer(payload)
	HTTP({
		url = config.endpoint,
		method = "POST",
		body = util.TableToJSON(payload),
		type = "application/json; charset=utf-8",
		headers = {
			["X-Sentry-Auth"] = sentryAuthHeader(),
		},
		success = function(code, body, headers)
			local result = util.JSONToTable(body) or {};

			if (detectRateLimiting(code, headers)) then
				return;
			elseif (code ~= 200) then
				local error = headers["X-Sentry-Error"] or result["error"];

				if (code >= 500) then
					WriteLog("Server is offline (%s), trying later", error or code);
					doBackoff(2);
					return
				elseif (code == 401) then
					WriteLog("Access denied - shutting down: %s", error or body);
					-- If sentry tells us to go away, go away properly
					config.endpoint = nil;
					return;
				else
					WriteLog("Got HTTP %d from the server: %s", code, error or body)
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
local function proccessException(err, stack, extra)
	if (not extra) then
		extra = {};
	end

	local payload = buildPayload(err, stack, extra);

	SendToServer(payload);

	return payload.event_id;
end

local function OnLuaError(is_runtime, rawErr, file, lineno, err, stack)
	if (not shouldReport(rawErr)) then
		return;
	end

	if (#stack == 0) then
		stack[1] = {
			name = is_runtime and "<unknown>" or "<compile>",
			source = '@' .. file,
			currentline = lineno,
		}
	end

	proccessException(err, stack);
end

function CaptureException(err, extra)
	if (not shouldReport(err)) then
		return nil;
	end

	local stack = getStack();

	err = stripFileData(err, stack);

	return proccessException(err, stack, extra);
end

local function xpcallCB(err)
	if (not shouldReport(err)) then
		return err;
	end

	local stack = getStack();

	local msg = stripFileData(err, stack);

	proccessException(msg, stack);

	-- Return the unmodified error
	return err;
end

function pcall(func, ...)
	local args = { ... };
	local extra = {};

	-- If the first argument is a table, it's configuring the exception handler
	if (type(func) == "table") then
		extra = func;
		func = table.remove(args, 1);
	end

	local id = pushTransaction(extra);
	local res = { xpcall(func, xpcallCB, unpack(args)) };
	popTransaction(id);

	return unpack(res);
end


--
-- Transaction Management
--
function SkipNext(msg)
	skipNext = msg;
end

DISABLE_TXN_PCALL = "no pcall only txn";
function ExecuteInTransactionSANE(name, txn, func, ...)
	if (name) then
		txn["culprit"] = name;
	end

	local id = pushTransaction(txn);
	local res;
	-- Danger zone!
	if (txn[DISABLE_TXN_PCALL]) then
		res = { true, func(...) };
	else
		res = { xpcall(func, xpcallCB, ...) };
	end
	popTransaction(id);

	local success = table.remove(res, 1);
	if (not success) then
		local err = res[1];
		SkipNext(err);
		-- Boom
		error(err, 0);
	end

	return unpack(res);
end

function ExecuteInTransaction(func, ...)
	-- vulgar hellcode
	local name;
	local txn = {};
	local args = { ... }

	if (type(func) == "string") then
		name = func;
		func = table.remove(args, 1);
	end

	if (type(func) == "table") then
		txn = func;
		func = table.remove(args, 1);
	end

	return ExecuteInTransactionSANE(name, txn, func, unpack(args));
end

function MergeContext(data)
	local txn = getCurrentTransaction();
	-- This might be suprising behaviour, but I don't have any better ideas
	if (not txn) then
		return;
	end

	table.Merge(txn.ctx, data);
end

function ClearContext()
	local txn = getCurrentTransaction();
	-- This might be suprising behaviour, but I don't have any better ideas
	if (not txn) then
		return;
	end

	txn.ctx = {};
end

function TagsContext(tags)
	MergeContext({ tags = tags });
end

function ExtraContext(exta)
	MergeContext({ extra = extra });
end

function UserContext(user)
	MergeContext({ user = user });
end


--
--    Detours
--
local detourMT = {}
detourMT.__index = detourMT;
function detourMT:__call(...)
	return self.override(self, ...);
end

function detourMT:_get(extra)
	-- I can't think of a sane way of doing this
	local p = self.path;
	if (#p == 1) then
		return g[p[1] .. extra];
	elseif (#p == 2) then
		return g[p[1]][p[2] .. extra];
	else
		error("Not implemented");
	end
end

function detourMT:_set(value, extra)
	extra = extra or "";
	local p = self.path;
	if (#p == 1) then
		g[p[1] .. extra] = value;
	elseif (#p == 2) then
		g[p[1]][p[2] .. extra] = value;
	else
		error("Not implemented");
	end
end

function detourMT:_reset_existing_detour()
	local detour = self:_get("_DT");
	if (not detour) then
		return false;
	end

	detour:Reset();
	return true;
end

function detourMT:_get_valid()
	if (self:_reset_existing_detour()) then
		return self:_get_valid();
	end
	local func = self:_get("");

	if (type(func) ~= "function") then
		return false;
	end

	local info = debug.getinfo(func, "S");
	if (info["source"] ~= "@" .. self.module) then
		return false;
	end

	return func;
end

function detourMT:Detour()
	local func = self:_get_valid();
	if (not func) then
		error("Can't detour!");
	end
	self.original = func;
	self:_set(self, "_DT");
	-- Engine functions won't talk to magical tables with the __call metafield. :(
	self:_set(function(...) return self(...) end);
end

function detourMT:Reset()
	self:_set(self.original);
end

function detourMT:Validate(module)
	return self:_get_valid() ~= false;
end

local function createDetour(func, target, expectedModule)
	local detour = {
		override = func,
		path = string.Split(target, "."),
		module = expectedModule,
	}
	setmetatable(detour, detourMT);

	if (not detour:Validate()) then
		return nil;
	end

	return detour;
end

local function concommandRun(detour, ply, command, ...)
	local cmd = command:lower();
	ExecuteInTransactionSANE(
		"cmd/" .. cmd,
		{
			tags = {
				concommand = cmd,
			},
			user = ply,
		},
		detour.original, ply, command, ...
	);
end

local function netIncoming(detour, len, ply)
	local id = net.ReadHeader();
	local name = util.NetworkIDToString(id);
	if (not name) then
		CaptureException(
			string.format("Unknown network message with ID %d", id),
			{
				user = ply,
				culprit = "net/" .. tostring(id),
			}
		)
		return;
	end

	local func = net.Receivers[name:lower()];
	if (not func) then
		CaptureException(
			string.format("Unknown network message with name %s", name),
			{
				user = ply,
				tags = {
					net_message = name,
				},
				culprit = "net/" .. name,
			}
		)
		return;
	end

	-- len includes the 16 bit int which told us the message name
	len = len - 16

	ExecuteInTransactionSANE(
		"net/" .. name,
		{
			user = ply,
			tags = {
				net_message = name,
			},
		},
		func, len, ply
	);
end

local HOOK_TXN_FORMAT = "hook/%s/%s";
local function actualHookCall(name, gm, ...)
	-- Heuristics: Pretty much any hook that operates on a player has the player as the first argument
	local ply = ...;
	if (not (type(ply) == "Player" and IsValid(ply))) then
		ply = nil;
	end

	local ctx = {
		[DISABLE_TXN_PCALL] = true,
		user = ply,
	}

	local hooks = hook.GetTable()[name];
	if (hooks) then
		local a, b, c, d, e, f;
		for hookname, func in pairs(hooks) do
			if (isstring(hookname)) then
				a, b, c, d, e, f = ExecuteInTransactionSANE(
					string.format(HOOK_TXN_FORMAT, name, hookname),
					ctx,
					func,
					...
				);
			elseif (IsValid(hookname)) then
				a, b, c, d, e, f = ExecuteInTransactionSANE(
					-- This won't be a great name, but it's the best we can do
					string.format(HOOK_TXN_FORMAT, name, tostring(hookname)),
					ctx,
					func,
					hookname,
					...
				);
			else
				hooks[hookname] = nil;
			end

			if (a ~= nil) then
				return a, b, c, d, e, f;
			end
		end
	end

	if (gm and gm[name]) then
		return ExecuteInTransactionSANE(
			string.format(HOOK_TXN_FORMAT, "GM", name),
			ctx,
			gm[name],
			gm,
			...
		);
	end
end

local function ulxHookCall(name, gm, ...)
	-- Heuristics: Pretty much any hook that operates on a player has the player as the first argument
	local ply = ...;
	if (not (type(ply) == "Player" and IsValid(ply))) then
		ply = nil;
	end

	local ctx = {
		[DISABLE_TXN_PCALL] = true,
		user = ply,
	}

	local hooks = hook.GetULibTable()[name];
	if (hooks) then
		local a, b, c, d, e, f, func;
		for i = -2, 2 do
			for hookname, t in pairs(hooks[i]) do
				func = t.fn;
				if (t.isstring) then
					a, b, c, d, e, f = ExecuteInTransactionSANE(
						string.format(HOOK_TXN_FORMAT, name, hookname),
						ctx,
						func,
						...
					);
				elseif (IsValid(hookname)) then
					a, b, c, d, e, f = ExecuteInTransactionSANE(
						-- This won't be a great name, but it's the best we can do
						string.format(HOOK_TXN_FORMAT, name, tostring(hookname)),
						ctx,
						func,
						hookname,
						...
					);
				else
					hooks[i][hookname] = nil;
				end

				if (a ~= nil and i > -2 and i < 2) then
					return a, b, c, d, e, f;
				end
			end
		end
	end

	if (gm and gm[name]) then
		return ExecuteInTransactionSANE(
			string.format(HOOK_TXN_FORMAT, "GM", name),
			ctx,
			gm[name],
			gm,
			...
		);
	end
end

local function hookCall(detour, name, ...)
	return ExecuteInTransactionSANE(nil, {
		tags = {
			hook = name,
		},
	}, detour.func, name, ...)
end

local hookTypes = {
	{
		override = actualHookCall,
		module = "lua/includes/modules/hook.lua",
	},
	{
		override = ulxHookCall,
		module = "lua/ulib/shared/hook.lua",
	},
	{
		override = ulxHookCall,
		module = "addons/ulib/lua/ulib/shared/hook.lua",
	},
}
local function detourHookCall()
	for _, hook in pairs(hookTypes) do
		local detour = createDetour(hookCall, "hook.Call", hook.module);
		if (detour) then
			detour.func = hook.override;
			return detour;
		end
	end

	return false;
end

local toDetour = {
	{
		target = "concommand.Run",
		override = concommandRun,
		module = "lua/includes/modules/concommand.lua",
	},
	{
		target = "net.Incoming",
		override = netIncoming,
		module = "lua/includes/extensions/net.lua",
	},
}
local ERR_PREDETOURED = "Cannot override function %q as it is already overidden! Maybe add it to no_detour?"
local function doDetours()
	local no_detour = {}
	for _, funcname in ipairs(config["no_detour"]) do
		no_detour[funcname] = true;
	end

	for _, deets in pairs(toDetour) do
		if (not no_detour[deets.target]) then
			local detour = createDetour(deets.override, deets.target, deets.module);
			if (not detour) then
				error(string.format(ERR_PREDETOURED, deets.target))
			end
			detour:Detour();
		end
	end

	if (not no_detour["hook.Call"]) then
		local detour = detourHookCall();
		if (not detour) then
			error(string.format(ERR_PREDETOURED, "hook.Call"))
		end
		detour:Detour();
	end
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

local settables = { "tags", "release", "environment", "server_name", "no_detour" }
function Setup(dsn, extra)
	parseDSN(dsn)

	if (extra) then
		for _, key in pairs(settables) do
			if (extra[key] ~= nil) then
				config[key] = extra[key];
			end
		end
	end

	if (not config["server_name"]) then
		config["server_name"] = GetHostName();
	end

	doDetours();

	luaerror.EnableRuntimeDetour(true);
	luaerror.EnableCompiletimeDetour(true);

	hook.Add("LuaError", "Sentry Integration", OnLuaError);

	-- Once the server has initialised, get all the things with a "version" field
	hook.Add("Initialize", "Sentry Integration", detectModules)
	-- Just in case we're being called in the Initialize hook, also get them now.
	detectModules();
end
