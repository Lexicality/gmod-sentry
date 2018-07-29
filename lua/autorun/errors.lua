local function throws(func, arg1, arg2)
	local foo = 8;
	local bar = arg1 .. arg2;
	func("oops");
end

local function level1(func, arg1)
	local two = "beans";
	throws(func, arg1, two);
end

local function level2(func)
	level1(func, "beans");
end

local function level3(func) level2(func) end
local function level4(func) level3(func) end
local function level5(func) level4(func) end


if SERVER then
	concommand.Add("oops", function() level5(error) end);
	concommand.Add("oops2", function() level5(Error) end);
	concommand.Add("oops3", function() level5(ErrorNoHalt) end);
	concommand.Add("oops4", function() error("oops") end);
else
	concommand.Add("cl_oops", function() level5(error) end);
	concommand.Add("cl_oops2", function() level5(Error) end);
	concommand.Add("cl_oops3", function() level5(ErrorNoHalt) end);
end