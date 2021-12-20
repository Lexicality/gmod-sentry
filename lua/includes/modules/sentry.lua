--[[
	Garry's Mod Sentry Integration
    Copyright 2018 Lex Robinson

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
]] --
---
-- Provides an interface to [Sentry](https://sentry.io) from GLua
--
-- [Github Page](https://github.com/lexicality/gmod-sentry/)
-- @module sentry
-- @author Lex Robinson
-- @copyright 2018 Lex Robinson
require("luaerror")
if not luaerror then
	error("Please make sure you've installed gm_luaerror correctly")
end

local GetHostName = GetHostName
local HTTP = HTTP
local IsValid = IsValid
local ServerLog = ServerLog
local SysTime = SysTime
local bit = bit
local error = error
local hook = hook
local ipairs = ipairs
local isstring = isstring
local luaerror = luaerror
local math = math
local net = net
local os = os
local pairs = pairs
local rawget = rawget
local setmetatable = setmetatable
local string = string
local system = system
local table = table
local tonumber = tonumber
local tostring = tostring
local type = type
local unpack = unpack
local util = util
local xpcall = xpcall
-- debugging
local debug = debug
local print = print
local PrintTable = PrintTable

local g = _G
module("sentry")

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
SDK_VALUE = {name = "GMSentry", version = "0.0.1"}
-- LuaJIT Style
Version = string.format("%s %s", SDK_VALUE.name, SDK_VALUE.version)
VersionNum = string.format(
	"%02d%02d%02d", string.match(SDK_VALUE.version, "(%d+).(%d+).(%d+)")
)

--
--    Utility Functions
--

--
-- Generates a v4 UUID without dashes
-- Copied from wirelib almost verbatim
-- @return a UUID in hexadecimal string format.
function UUID4()
	-- It would be easier to generate this by word rather than by byte, but
	-- MSVC's RAND_MAX = 0x7FFF, which means math.random(0, 0xFFFF) won't
	-- return all possible values.
	local bytes = {}
	for i = 1, 16 do
		bytes[i] = math.random(0, 0xFF)
	end
	bytes[7] = bit.bor(0x40, bit.band(bytes[7], 0x0F))
	bytes[9] = bit.bor(0x80, bit.band(bytes[7], 0x3F))
	return string.format(
		"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		unpack(bytes)
	)
end

---
-- Generates an ISO 8601/RFC 6350 formatted date
-- @within util
-- @param time The unix timestamp to generate the date from
-- @return The date string
function ISODate(time)
	return os.date("!%Y-%m-%dT%H:%M:%S", time)
end

---
-- Generates a pretty printed name of the current operating sytem
-- @within util
-- @return "Windows", "macOS", "Linux" or nil.
function GetOSName()
	if system.IsWindows() then
		return "Windows"
	elseif system.IsOSX() then
		return "macOS"
	elseif system.IsLinux() then
		return "Linux"
	end
	return nil
end

---
-- Writes a logline to the Server log, using string.format
-- @within util
-- @param message Logline to write
-- @param ... Values to format into it
local function WriteLog(message, ...)
	ServerLog(string.format("Sentry: %s\n", message:format(...)))
end

--
--    Module Detection
--

---
-- All the modules Sentry has detected.
-- Anything added to this will also be sent to Sentry
-- @usage sentry.DetectedModules["foo"] = "7.2"
DetectedModules = {}

---
-- More complex ways of detecting a module's version
-- @field _
-- @usage sentry.DetectionFuncs["global name"] = function(global_value) return "version", "optional override name" end
DetectionFuncs = {
	mysqloo = function(mysqloo)
		return string.format("%d.%d", mysqloo.VERSION, mysqloo.MINOR_VERSION or 0)
	end,
	CPPI = function(CPPI)
		local name = CPPI:GetName()
		local version = CPPI:GetVersion()
		if version == CPPI.CPPI_NOT_IMPLEMENTED then
			-- ???
			return nil
		end
		return version, name
	end,
	ulx = function(ulx)
		-- Why is this better than ulx.version
		local ULib = g["ULib"]
		if ULib and ULib.pluginVersionStr then
			return ULib.pluginVersionStr("ULX")
		end
		return ulx.version or ulx.VERSION
	end,
	ULib = function(ULib)
		if ULib.pluginVersionStr then
			return ULib.pluginVersionStr("ULib")
		end
		return ULib.version or ULib.VERSION
	end,
	GM = function(GM)
		if not GM.Version then
			return nil
		end
		return GM.Version, string.format("Gamemode: %s", GM.Name)
	end,
}
DetectionFuncs["GAMEMODE"] = DetectionFuncs["GM"]

local LUAJIT_VERSION = "(.+) (%d+%.%d+%.%d+)"
---
-- Loops through _G and tries to find anything with some variant of a VERSION field.
local function detectModules()
	local VERSION = g["VERSION"]

	for name, value in pairs(g) do
		local func = DetectionFuncs[name]
		if func then
			-- Overrides
			local _, version, override = xpcall(func, CaptureException, value)

			if version then
				DetectedModules[override or name] = tostring(version)
			end
		elseif type(value) == "table" and name ~= "sentry" then
			-- Magic guessing game
			local version = rawget(value, "version") or rawget(value, "Version") or
                				rawget(value, "VERSION")

			if version and version ~= VERSION and type(version) ~= "function" then
				version = tostring(version)

				-- Try and deal with LuaJIT style version strings
				local override, realversion = string.match(version, LUAJIT_VERSION)
				if override then
					version = realversion
				end

				DetectedModules[override or name] = version
			end
		end
	end
end

--
--    Rate Limiting
--
local retryAfter = nil
local skipNext = nil
---
-- Checks if an error should be reported to sentry
-- @param err The FULL error message including embedded where line
-- @return true to report, false to discard
local function shouldReport(err)
	if not config.endpoint then
		return false
	elseif retryAfter ~= nil then
		local now = SysTime()
		if retryAfter > now then
			return false
		end

		retryAfter = nil
	elseif string.find(err, "ISteamHTTP isn't available") then
		return false
	end

	if skipNext == err then
		skipNext = nil
		return false
	end
	skipNext = nil

	return true
end

---
-- Disables sending messages to sentry for a period
-- @param backoff how many seconds to wait
local function doBackoff(backoff)
	local expires = SysTime() + backoff
	if retryAfter == nil or retryAfter < expires then
		WriteLog("Rate Limiting for %d seconds!", backoff)
		retryAfter = expires
	end
end

---
-- Detects if the server is telling us to back off and by how much
-- @param code HTTP status code in number form
-- @param headers Table of HTTP response headers
-- @return true if the server is unhappy with us
local function detectRateLimiting(code, headers)
	local backoff = tonumber(headers["Retry-After"])
	-- Shouldn't happen, but might
	if code == 429 and not backoff then
		backoff = 20
	end

	if not backoff then
		return false
	end

	doBackoff(backoff)

	return true
end

--
--    File Identification
--
local ADDON_FILE_PATTERN = "^@addons/([^/]+)/lua/(.*).lua$"
local GAMEMODE_FILE_PATTERN = "^@gamemodes/([^/]+)/(.*).lua$"
local ADDON_GAMEMODE_FILE_PATTERN = "^@addons/[^/]+/gamemodes/([^/]+)/(.*).lua$"
local OTHER_FILE_PATTERN = "^@lua/(.*).lua$"
---
-- Generates a "module" name from a lua path
-- @param path A full stacktrace lua path like "@addons/foo/lua/bar/baz.lua"
-- @return A pretty name like "foo.bar.baz" or "unknown" if the path makes no sense
local function modulify(path)
	if path == "=[C]" then
		return "engine"
	elseif path == "@lua_run" then
		return "lua_run"
	end

	local addon, rest = string.match(path, ADDON_FILE_PATTERN)
	if addon then
		return addon .. "." .. rest:gsub("/", ".")
	end

	local gamemode, rest = string.match(path, GAMEMODE_FILE_PATTERN)
	if not gamemode then
		gamemode, rest = string.match(path, ADDON_GAMEMODE_FILE_PATTERN)
	end
	if gamemode then
		return gamemode .. "." .. rest:gsub("/", ".")
	end

	local rest = string.match(path, OTHER_FILE_PATTERN)
	if not rest then
		return "unknown"
	end

	local name, id = luaerror.FindWorkshopAddonFileOwner(path:sub(2))
	if not name then
		return "unknown." .. rest:gsub("/", ".")
	end

	-- Asciify name
	name = name:lower():gsub("[^%w]+", "-"):gsub("%-+", "-"):gsub(
		"^%-*(.-)%-*$", "%1"
	)
	-- Lua doesn't do unicode, so if the workshop name is in cyrilic or something, it'll now be empty
	if name:len() < 3 then
		-- Heck
		name = "workshop-" .. id
	end

	return name .. "." .. rest:gsub("/", ".")
end

--
--    Stack Reverse Engineering
--

---
-- Turns a lua stacktrace into a Sentry stacktrace
-- @param stack Lua stacktrace in debug.getinfo style
-- @return A reversed stacktrace with different field names
local function sentrifyStack(stack)
	-- Sentry likes stacks in the oposite order to lua
	stack = table.Reverse(stack)

	-- The first entry from LuaError is sometimes useless
	if stack[#stack]["source"] == "=[C]" and stack[#stack]["name"] == "" then
		table.remove(stack)
	end
	-- If someone has called `error`, remove it from the stack trace
	if stack[#stack]["source"] == "=[C]" and stack[#stack]["name"] == "error" then
		table.remove(stack)
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
	return {frames = ret}
end

---
-- Extract the current stacktrace
-- @return A Lua stacktrace
local function getStack()
	local level = 3 -- 1 = this, 2 = CaptureException

	local stack = {}
	while true do
		local info = debug.getinfo(level, "Sln")
		if not info then
			break
		end

		stack[level - 2] = info

		level = level + 1
	end

	return stack
end

---
-- Removes file info from lua errors by matching it with the stacktrace
-- If the file does not occur in the stacktrace, it does not strip it.
-- @param err an error like "lua/foo.lua:5: oops"
-- @param stack The error's stacktrace
-- @return Hopefully a nice error like "oops" or the full error if not
local function stripFileData(err, stack)
	local match, file, line = string.match(err, "^((.+):(%d+): ).+$")
	if not match then
		return err
	end

	for _, frame in pairs(stack) do
		if frame["source"] == "@" .. file and tostring(frame["currentline"]) ==
			tostring(line) then
			err = err:sub(#match + 1)
			break
		end
	end

	return err
end

local ADDON_BLAME_PATTERN = "^addons/([^/]+)/"
local GAMEMODE_BLAME_PATTERN = "^gamemodes/([^/]+)/"
---
-- Creates tags from the stack trace to help point the finger at the error's source
-- @param stack The full Lua stacktrace
-- @return An array of tags in sentry format
local function calculateBlame(stack)
	for _, frame in pairs(stack) do
		if frame["source"] ~= "=[C]" then
			local source = frame["source"]:sub(2)

			local wsname, wsid = luaerror.FindWorkshopAddonFileOwner(source)
			if wsname then
				return {{"addon", "workshop-" .. wsid}, {"addon-name", wsname}}
			end

			local addon = string.match(source, ADDON_BLAME_PATTERN)
			if addon then
				return {{"addon", addon}}
			end

			local gamemode = string.match(source, GAMEMODE_BLAME_PATTERN)
			if gamemode then
				return {{"gamemode", gamemode}}
			end
		end
	end

	return {}
end

--
--    Transaction Management
--
local transactionStack = {}
---
-- Checks if Sentry thinks a transaction is active
-- Ideally true, but could be false if an undetoured entrypoint is used
-- @within Transactions
-- @return true or false
function IsInTransaction()
	return #transactionStack > 0
end

---
-- Adds a transaction to the stack
-- @param data The transaction's state
-- @return The transaction's ID for popping
local function pushTransaction(data)
	local txn = {data = data, ctx = {}, id = UUID4()}

	transactionStack[#transactionStack + 1] = txn

	return txn.id
end

---
-- Pops a transaction from the stack
-- If the transaction is not at the head of the stack, pops everything above it too.
-- @param id The transaction's ID
-- @return The transaction's state
local function popTransaction(id)
	for i, txn in pairs(transactionStack) do
		if txn.id == id then
			-- Nuke everything above this tranasction in the stack
			while transactionStack[i] do
				table.remove(transactionStack, i)
			end

			-- If this is the last transaction, discard any pending skips
			-- "Bug": If you start a transaction from within builtin xpcall inside an
			-- active transaction, that transaction fails and you immediately call that
			-- transaction again and it fails again, the second error won't be reported
			-- to sentry.
			-- If you run into this bug, reevaulate your life choices
			if not IsInTransaction() then
				skipNext = nil
			end

			return txn.data
		end
	end

	error("Unknown Transaction '" .. tostring(id) .. "'!")
end

---
-- Merges all active transactions oldest to newest to get a composite block of data
-- Also merges any context overrides from each transaction at the time
-- @return A nice block of transaction context, or empty table if no transactions are active
local function getTransactionData()
	local res = {}

	for _, txn in ipairs(transactionStack) do
		table.Merge(res, txn.data)
		table.Merge(res, txn.ctx)
	end

	return res
end

---
-- Gets the top transaction on the stack
-- @return The full transaction meta object, or nil if there is no transaction active
local function getCurrentTransaction()
	return transactionStack[#transactionStack]
end

--
--    Context Management
--
---
-- Converts user context to player data
-- Requires there to be a "user" field in extra and requires it to be a valid player object
-- @param extra The fully merged frame context
-- @return A sentry formatted userdata or nil
local function getUserContext(extra)
	local ply = extra["user"]
	if not IsValid(ply) then
		return nil
	end

	return {
		id = ply:SteamID(),
		username = ply:Nick(),
		ip = ply:IPAddress(),
		steamid64 = ply:SteamID64(),
	}
end

---
-- Converts stack context into Sentry context objects
-- @param extra The fully merged frame context
-- @return A sentry formatted object to go into the "contexts" field
local function getContexts(extra)
	return {
		os = {name = GetOSName()},
		runtime = {name = "Garry's Mod", version = g["VERSIONSTR"]},
		app = {app_start_time = ISODate(math.floor(os.time() - SysTime()))},
		user = getUserContext(extra),
	}
end

---
-- Generate a set of sentry formatted tags from the inital setup & passed context
-- @param extra The fully merged frame context
-- @return A sentry formatted object to go into the "tags" field
local function getTags(extra)
	local tags = {}

	for name, value in pairs(config.tags) do
		table.insert(tags, {name, value})
	end

	-- Sentry would like extra tag values to suppliment the SDK tags when you send
	--  them, but will still only allow one of each tag to exist.
	-- I'm not entirely sure why, but best to do what the server asks for.
	if extra["tags"] then
		for name, value in pairs(extra.tags) do
			table.insert(tags, {name, value})
		end
	end

	return tags
end

--
--    Payload
--
---
-- Build a sentry JSON payload from an error
-- This will merge in transaction data & SDK preset values
-- @param err The normalised error string (no filepath included)
-- @param stacktrace The Lua stacktrace for the error
-- @param extra Any additional context for the error
-- @return A full sentry object ready to be JSON'd and uplodaded
local function buildPayload(err, stacktrace, extra)
	local txn = getTransactionData()
	table.Merge(txn, extra)

	local tags = getTags(txn)
	table.Add(tags, calculateBlame(stacktrace))

	return {
		event_id = UUID4(),
		timestamp = ISODate(os.time()),
		logger = "sentry",
		platform = "other",
		sdk = SDK_VALUE,
		exception = {
			{type = "error", value = err, stacktrace = sentrifyStack(stacktrace)},
		},
		modules = DetectedModules,
		contexts = getContexts(txn),
		tags = tags,
		environment = config["environment"],
		release = config["release"],
		server_name = config["server_name"],
		level = txn["level"],
		extra = txn["extra"],
		culprit = txn["culprit"],
	}
end

--
--    Actual HTTP Integration
--
local SENTRY_HEADER_FORMAT = ("Sentry sentry_version=7, " ..
                             	"sentry_client=%s/%s, " .. "sentry_timestamp=%d, " ..
                             	"sentry_key=%s")
---
-- Build the sentry security header
-- @return A string to go in the X-Sentry-Auth header
local function sentryAuthHeader()
	local header = SENTRY_HEADER_FORMAT:format(
		SDK_VALUE.name, SDK_VALUE.version, os.time(), config.publickey,
		config.privatekey
	)
	-- Sentry <9 needs a secret key
	if config.privatekey then
		header = header .. (", sentry_secret=%s"):format(config.privatekey)
	end
	return header
end

---
-- Asynchronously upload a payload to the Sentry servers.
-- Returns immediately regardless of success.
-- @param payload a Sentry formatted payload table
local function SendToServer(payload)
	HTTP(
		{
			url = config.endpoint,
			method = "POST",
			body = util.TableToJSON(payload),
			type = "application/json; charset=utf-8",
			headers = {["X-Sentry-Auth"] = sentryAuthHeader()},
			success = function(code, body, headers)
				local result = util.JSONToTable(body) or {}

				if detectRateLimiting(code, headers) then
					return
				elseif code ~= 200 then
					local error = headers["X-Sentry-Error"] or result["error"]

					if code >= 500 then
						WriteLog("Server is offline (%s), trying later", error or code)
						doBackoff(2)
						return
					elseif code == 401 then
						WriteLog("Access denied - shutting down: %s", error or body)
						-- If sentry tells us to go away, go away properly
						config.endpoint = nil
						return
					else
						WriteLog("Got HTTP %d from the server: %s", code, error or body)
						return
					end
				end

				-- Debugging
				print("Success! Event stored with ID " .. (result["id"] or "?"))
			end,
			failed = function(reason)
				-- This is effectively useless
				WriteLog("HTTP request failed: %s", reason)
			end,
		}
	)
end

--
--    Reporting Functions
--
---
-- Process & upload a normalised error.
-- @param err The normalised error string (no filepath included)
-- @param stack The Lua stacktrace for the error
-- @param extra Any additional context for the error
-- @return The generated event ID
local function proccessException(err, stack, extra)
	if not extra then
		extra = {}
	end

	local payload = buildPayload(err, stack, extra)

	SendToServer(payload)

	return payload.event_id
end

---
-- The gm_luaerror hook at the heart of this module
-- @param is_runtime If this error was a compile error or a runtime error. Largely irrelevent.
-- @param rawErr The full error that gets printed in console.
-- @param file The filename extracted from rawErr
-- @param lineno The line number extracte from rawErr
-- @param err The error string extracted from rawErr
-- @param stack The captured stack trace for the error. May be empty
-- @return Nothing or you'll break everything
local function OnLuaError(is_runtime, rawErr, file, lineno, err, stack)
	if not shouldReport(rawErr) then
		return
	end

	if #stack == 0 then
		stack[1] = {
			name = is_runtime and "<unknown>" or "<compile>",
			source = "@" .. file,
			currentline = lineno,
		}
	end

	proccessException(err, stack)
end

---
-- Captures an exception for sentry, using the current stack as the error's stack
-- Most useful inside an xpcall handler
-- @param err The raw Lua error that happened, with or without file details
-- @param extra Any other information about the error to upload to Sentry with it
-- @return The generated error's ID or nil if it was automatically discarded
function CaptureException(err, extra)
	if not shouldReport(err) then
		return nil
	end

	local stack = getStack()

	err = stripFileData(err, stack)

	return proccessException(err, stack, extra)
end

---
-- The callback for xpcall to upload errors to sentry
-- @param err Captured error
-- @return err
local function xpcallCB(err)
	if not shouldReport(err) then
		return err
	end

	local stack = getStack()

	local msg = stripFileData(err, stack)

	proccessException(msg, stack)

	-- Return the unmodified error
	return err
end

---
-- Works like [normal pcall](https://www.lua.org/manual/5.1/manual.html#pdf-pcall)
-- but uploads the error to Sentry as well as returning it
-- @param[opt] extra Other info to send to the server if func errors
-- @param func The function to pcall
-- @param ... Arguments to pass to func
-- @return Its first result is the status code (a boolean), which is true if the call succeeds without errors. In such case, pcall also returns all results from the call, after this first result. In case of any error, pcall returns false plus the error message.
function pcall(func, ...)
	local args = {...}
	local extra = {}

	-- If the first argument is a table, it's configuring the exception handler
	if type(func) == "table" then
		extra = func
		func = table.remove(args, 1)
	end

	local id = pushTransaction(extra)
	local res = {xpcall(func, xpcallCB, unpack(args))}
	popTransaction(id)

	return unpack(res)
end

--
-- Transaction Management
--
---
-- Skip the next message if it matches this message
-- @param msg The full raw lua error including file/line info
function SkipNext(msg)
	skipNext = msg
end

---
-- [INTERNAL] Executes a function in transaction context
-- @within Transactions
-- @param name The name of the transaction or nil if not applicable
-- @param txn The data to attach to the transaction
-- @param func The function to execute
-- @param ... Arguments to pass to the function
-- @return Whatever func returns
function ExecuteTransaction(name, txn, func, ...)
	if name then
		txn["culprit"] = name
	end

	local noXPCall = IsInTransaction()

	local id = pushTransaction(txn)
	local res

	-- If we're already inside a transaction, we don't need to xpcall because the
	-- error will bubble all the way up to the root txn
	if noXPCall then
		res = {true, func(...)}
	else
		res = {xpcall(func, xpcallCB, ...)}
	end

	popTransaction(id)

	local success = table.remove(res, 1)
	if not success then
		local err = res[1]
		SkipNext(err)
		-- Boom
		error(err, 0)
	end

	return unpack(res)
end

---
-- Executes a function in transaction context.
-- If the function throws an error, the error will be reported to sentry and then will be re-raised.
-- If you don't want the error re-raised, use sentry.pcall
-- Both name and txn are optional
-- @usage sentry.ExecuteInTransaction("My Thing", mything)
-- @usage sentry.ExecuteInTransaction({ tags = { mything = "awesome"} }, mything)
-- @param[opt] name The name of the transaction or nil if not applicable
-- @param[opt] txn The data to attach to the transaction
-- @param func The function to execute
-- @param ... Arguments to pass to the function
-- @return Whatever func returns
function ExecuteInTransaction(...)
	-- vulgar hellcode
	local a, b = ...
	a, b = type(a), type(b)

	if a == "string" or a == "nil" then
		if b == "table" then
			return ExecuteTransaction(...)
		else
			return ExecuteTransaction(..., {}, select(2, ...))
		end
	elseif a == "table" then
		return ExecuteTransaction(nil, ...)
	else
		return ExecuteTransaction(nil, {}, ...)
	end
end

---
-- Add data to the current transaction's context.
-- Anything here will override the transaction's starting values
-- Does nothing if no transaction is active
-- @within Transactions
-- @usage sentry.MergeContext({ culprit = "your mum" })
-- @param data Data to add
function MergeContext(data)
	local txn = getCurrentTransaction()
	-- This might be suprising behaviour, but I don't have any better ideas
	if not txn then
		return
	end

	table.Merge(txn.ctx, data)
end

---
-- Remove any extra data from the current transaction.
-- Does not affect the data the transaction was started with.
-- Does nothing if no transaction is active
-- @within Transactions
function ClearContext()
	local txn = getCurrentTransaction()
	-- This might be suprising behaviour, but I don't have any better ideas
	if not txn then
		return
	end

	txn.ctx = {}
end

---
-- Merge tags into the current transaction's context
-- Does nothing if no transaction is active
-- @within Transactions
-- @usage sentry.TagsContext({ somecondition = "passed" })
-- @param tags A table of tag names as keys, values as values
function TagsContext(tags)
	MergeContext({tags = tags})
end

---
-- Merge the extra field into the current transaction's context
-- Does nothing if no transaction is active
-- @within Transactions
-- @usage sentry.ExtraContext({ numplayers = 23 })
-- @param tags A table of arbitrary data to send to Sentry
function ExtraContext(extra)
	MergeContext({extra = extra})
end

---
-- Set the current player for this context
-- Does nothing if no transaction is active
-- @within Transactions
-- @usage sentry.UserContext(ply)
-- @param user A player object
function UserContext(user)
	MergeContext({user = user})
end

--
--    Detours
--
local detourMT = {}
detourMT.__index = detourMT
function detourMT:__call(...)
	return self.override(self, ...)
end

function detourMT:_get(extra)
	-- I can't think of a sane way of doing this
	local p = self.path
	if #p == 1 then
		return g[p[1] .. extra]
	elseif #p == 2 then
		return g[p[1]][p[2] .. extra]
	else
		error("Not implemented")
	end
end

function detourMT:_set(value, extra)
	extra = extra or ""
	local p = self.path
	if #p == 1 then
		g[p[1] .. extra] = value
	elseif #p == 2 then
		g[p[1]][p[2] .. extra] = value
	else
		error("Not implemented")
	end
end

function detourMT:_reset_existing_detour()
	local detour = self:_get("_DT")
	if not detour then
		return false
	end

	detour:Reset()
	return true
end

function detourMT:_get_valid()
	if self:_reset_existing_detour() then
		return self:_get_valid()
	end
	local func = self:_get("")

	if type(func) ~= "function" then
		return false
	end

	local info = debug.getinfo(func, "S")
	if info["source"] ~= "@" .. self.module then
		return false
	end

	return func
end

function detourMT:Detour()
	local func = self:_get_valid()
	if not func then
		error("Can't detour!")
	end
	self.original = func
	self:_set(self, "_DT")
	-- Engine functions won't talk to magical tables with the __call metafield. :(
	self:_set(
		function(...)
			return self(...)
		end
	)
end

function detourMT:Reset()
	self:_set(self.original)
end

function detourMT:Validate(module)
	return self:_get_valid() ~= false
end

---
-- Replaces a function with a custom one.
-- Does nothing if something else has already overriden the function.
-- @param func The new function to use
-- @param target The target to override (eg "hook.Call")
-- @param expectedModule Where the target is supposed to be (eg "lua/includes/modules/hook.lua")
-- @return The detour object if the target is acceptable, false if it's not.
local function createDetour(func, target, expectedModule)
	local detour = {
		override = func,
		path = string.Split(target, "."),
		module = expectedModule,
	}
	setmetatable(detour, detourMT)

	if not detour:Validate() then
		return nil
	end

	return detour
end

local function concommandRun(detour, ply, command, ...)
	local cmd = command:lower()
	ExecuteTransaction(
		"cmd/" .. cmd, {tags = {concommand = cmd}, user = ply}, detour.original, ply,
		command, ...
	)
end

local function netIncoming(detour, len, ply)
	local id = net.ReadHeader()
	local name = util.NetworkIDToString(id)
	if not name then
		CaptureException(
			string.format("Unknown network message with ID %d", id),
			{user = ply, culprit = "net/" .. tostring(id)}
		)
		return
	end

	local func = net.Receivers[name:lower()]
	if not func then
		CaptureException(
			string.format("Unknown network message with name %s", name),
			{user = ply, tags = {net_message = name}, culprit = "net/" .. name}
		)
		return
	end

	-- len includes the 16 bit int which told us the message name
	len = len - 16

	ExecuteTransaction(
		"net/" .. name, {user = ply, tags = {net_message = name}}, func, len, ply
	)
end

local HOOK_TXN_FORMAT = "hook/%s/%s"
local function actualHookCall(name, gm, ...)
	-- Heuristics: Pretty much any hook that operates on a player has the player as the first argument
	local ply = ...
	if not (type(ply) == "Player" and IsValid(ply)) then
		ply = nil
	end

	local ctx = {user = ply}

	local hooks = hook.GetTable()[name]
	if hooks then
		local a, b, c, d, e, f
		for hookname, func in pairs(hooks) do
			if isstring(hookname) then
				a, b, c, d, e, f = ExecuteTransaction(
					string.format(HOOK_TXN_FORMAT, name, hookname), ctx, func, ...
				)
			elseif IsValid(hookname) then
				-- This won't be a great name, but it's the best we can do
				a, b, c, d, e, f = ExecuteTransaction(
					string.format(HOOK_TXN_FORMAT, name, tostring(hookname)), ctx, func,
					hookname, ...
				)
			else
				hooks[hookname] = nil
			end

			if a ~= nil then
				return a, b, c, d, e, f
			end
		end
	end

	if gm and gm[name] then
		return ExecuteTransaction(
			string.format(HOOK_TXN_FORMAT, "GM", name), ctx, gm[name], gm, ...
		)
	end
end

local function ulxHookCall(name, gm, ...)
	-- Heuristics: Pretty much any hook that operates on a player has the player as the first argument
	local ply = ...
	if not (type(ply) == "Player" and IsValid(ply)) then
		ply = nil
	end

	local ctx = {user = ply}

	local hooks = hook.GetULibTable()[name]
	if hooks then
		local a, b, c, d, e, f, func
		for i = -2, 2 do
			for hookname, t in pairs(hooks[i]) do
				func = t.fn
				if t.isstring then
					a, b, c, d, e, f = ExecuteTransaction(
						string.format(HOOK_TXN_FORMAT, name, hookname), ctx, func, ...
					)
				elseif IsValid(hookname) then
					-- This won't be a great name, but it's the best we can do
					a, b, c, d, e, f = ExecuteTransaction(
						string.format(HOOK_TXN_FORMAT, name, tostring(hookname)), ctx, func,
						hookname, ...
					)
				else
					hooks[i][hookname] = nil
				end

				if a ~= nil and i > -2 and i < 2 then
					return a, b, c, d, e, f
				end
			end
		end
	end

	if gm and gm[name] then
		return ExecuteTransaction(
			string.format(HOOK_TXN_FORMAT, "GM", name), ctx, gm[name], gm, ...
		)
	end
end

local function hookCall(detour, name, ...)
	return ExecuteTransaction(nil, {tags = {hook = name}}, detour.func, name, ...)
end

local hookTypes = {
	{override = actualHookCall, module = "lua/includes/modules/hook.lua"},
	{override = ulxHookCall, module = "lua/ulib/shared/hook.lua"},
	{override = ulxHookCall, module = "addons/ulib/lua/ulib/shared/hook.lua"},
}
---
-- Work out how to detour hook.Call
-- hook.Call is a popular override target, so a bit of custom logic is needed to
--  succeed against things like ULib
-- @return Detour object if successful, false otherwise
local function detourHookCall()
	for _, hook in pairs(hookTypes) do
		local detour = createDetour(hookCall, "hook.Call", hook.module)
		if detour then
			detour.func = hook.override
			return detour
		end
	end

	return false
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
local ERR_PREDETOURED =
	"Cannot override function %q as it is already overidden! Maybe add it to no_detour?"
---
-- Detour every function that hasn't been disabled with config.no_detour
-- Raises an error if a function can't be detoured
local function doDetours()
	local no_detour = {}
	for _, funcname in ipairs(config["no_detour"]) do
		no_detour[funcname] = true
	end

	for _, deets in pairs(toDetour) do
		if not no_detour[deets.target] then
			local detour = createDetour(deets.override, deets.target, deets.module)
			if not detour then
				error(string.format(ERR_PREDETOURED, deets.target))
			end
			detour:Detour()
		end
	end

	if not no_detour["hook.Call"] then
		local detour = detourHookCall()
		if not detour then
			error(string.format(ERR_PREDETOURED, "hook.Call"))
		end
		detour:Detour()
	end
end

--
-- Initial Configuration
--
local DSN_FORMAT = "^([^:]+)://([^:]+)@([^/]+)(.*/)(.+)$"
---
-- Validates a sentry DSN and stores it in the config
-- @param dsn The passed string
local function parseDSN(dsn)
	local scheme, publickey, host, path, project =
		string.match(dsn, DSN_FORMAT)
	if not (scheme and publickey and host and project) then
		error("Malformed DSN!")
	end
	if privatekey == "" then
		privatekey = nil
	end
	config.privatekey = privatekey
	config.publickey = publickey
	config.projectID = project
	config.endpoint = scheme .. "://" .. host .. "/api/" .. project .. "/store/"
end

local settables = {"tags", "release", "environment", "server_name", "no_detour"}
---
-- Configures and activates Sentry
-- @usage sentry.Setup("https://key@sentry.io/1337", {server_name="server 7", release="v23", environment="production"})
-- @param dsn The DSN sentry gave you when you set up your project
-- @param[opt] extra Additional config values to store in sentry. Valid keys `tags`, `release`, `environment`, `server_name`, `no_detour`
function Setup(dsn, extra)
	parseDSN(dsn)

	if extra then
		for _, key in pairs(settables) do
			if extra[key] ~= nil then
				config[key] = extra[key]
			end
		end
	end

	if not config["server_name"] then
		config["server_name"] = GetHostName()
	end

	doDetours()

	luaerror.EnableRuntimeDetour(true)
	luaerror.EnableCompiletimeDetour(true)

	hook.Add("LuaError", "Sentry Integration", OnLuaError)

	-- Once the server has initialised, get all the things with a "version" field
	hook.Add("Initialize", "Sentry Integration", detectModules)
	-- Just in case we're being called in the Initialize hook, also get them now.
	detectModules()
end
