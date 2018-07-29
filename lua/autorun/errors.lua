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
