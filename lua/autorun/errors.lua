local function throws(arg1, arg2)
	local foo = 8;
	local bar = arg1 .. arg2;
	error("oops");
end

local function level1(arg1)
	local two = "beans";
	throws(arg1, two);
end

local function level2(func)
	level1("beans");
end

local function level3() level2() end
local function level4() level3() end
local function level5() level4() end


if SERVER then
	concommand.Add("oops", function() level5() end);
else
	concommand.Add("cl_oops", function() level5() end);
end

function drspang()
	local res, err = xpcall(level5, sentry.CaptureException)
	if (not res and err) then
		ErrorNoHalt(err);
	end
end

function drspangles()
	sentry.pcall(level5)
end

hook.Add("One", "aoeu", function() error("Oops") end);
hook.Add("Two", "ueoa", function() hook.Run("One") end)
hook.Add("Three", "spang", function() hook.Run("Two") end)
hook.Add("Four", "flang", function() hook.Run("Three") end)
concommand.Add("hookception", function() hook.Run("Four") end)
