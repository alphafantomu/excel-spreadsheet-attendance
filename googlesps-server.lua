

local require = function(moduleName)
    local generator = loadstring([[
        local luvi = require('luvi')
        local bundle = luvi.bundle
        local pathJoin = luvi.path.join
        local env = require('env')
        local os = require('ffi').os
        local uv = require('uv')

        local realRequire = _G.require

        local tmpBase = os == "Windows" and (env.get("TMP") or uv.cwd()) or
                                            (env.get("TMPDIR") or '/tmp')
        local binExt = os == "Windows" and ".dll" or ".so"

        -- Package sources
        -- $author/$name@$version -> resolves to hash, cached in memory
        -- bundle:full/bundle/path
        -- full/unix/path
        -- C:\\full\windows\path

        local fileCache = {}
        local function readFile(path)
          assert(path)
          local data = fileCache[path]
          if data ~= nil then return data end
          local prefix = path:match("^bundle:/*")
          if prefix then
            data = bundle.readfile(path:sub(#prefix + 1))
          else
            local stat = uv.fs_stat(path)
            if stat and stat.type == "file" then
              local fd = uv.fs_open(path, "r", 511)
              if fd then
                data = uv.fs_read(fd, stat.size, -1)
                uv.fs_close(fd)
              end
            end
          end
          fileCache[path] = data and true or false
          return data
        end

        local function scanDir(path)
          local bundlePath = path:match("^bundle:/*(.*)")
          if bundlePath then
            local names, err = bundle.readdir(bundlePath)
            if not names then return nil, err end
            local i = 1
            return function ()
              local name = names[i]
              if not name then return end
              i = i + 1
              local stat = assert(bundle.stat(bundlePath .. "/" .. name))
              return {
                name = name,
                type = stat.type,
              }
            end
          else
            local req, err = uv.fs_scandir(path)
            if not req then return nil, err end
            return function ()
              local name, typ = uv.fs_scandir_next(req)
              if type(name) == "table" then
                return name
              else
                return {
                  name = name,
                  type = typ
                }
              end
            end
          end
        end

        local statCache = {}
        local function statFile(path)
          local stat, err
          stat = statCache[path]
          if stat then return stat end
          local bundlePath = path:match("^bundle:/*(.*)")
          if bundlePath then
            stat, err = bundle.stat(bundlePath)
          else
            stat, err = uv.fs_stat(path)
          end
          if stat then
            statCache[path] = stat
            return stat
          end
          return nil, err or "Problem statting: " .. path
        end


        local dirCache = {}
        local function isDir(path)
          assert(path)
          local is = dirCache[path]
          if is ~= nil then return is end
          local prefix = path:match("^bundle:/*")
          local stat
          if prefix then
            stat = bundle.stat(path:sub(#prefix + 1))
          else
            stat = uv.fs_stat(path)
          end
          is = stat and (stat.type == "directory") or false
          dirCache[path] = is
          return is
        end


        local types = { ".lua", binExt }

        local function fixedRequire(path)
          assert(path)
          local fullPath = path
          local data = readFile(fullPath)
          if not data then
            for i = 1, #types do
              fullPath = path .. types[i]
              data = readFile(fullPath)
              if data then break end
              fullPath = pathJoin(path, "init" .. types[i])
              data = readFile(fullPath)
              if data then break end
            end
            if not data then return end
          end
           local prefix = fullPath:match("^bundle:")
           local normalizedPath = fullPath
           if prefix == "bundle:" and bundle.base then
             normalizedPath = fullPath:gsub(prefix, bundle.base)
           end

          return data, fullPath, normalizedPath
        end


        local skips = {}
        local function moduleRequire(base, name)
          assert(base and name)
          while true do
            if not skips[base] then
              local mod, path, key
              if isDir(pathJoin(base, "libs")) then
                mod, path, key = fixedRequire(pathJoin(base, "libs", name))
                if mod then return mod, path, key end
              end
              if isDir(pathJoin(base, "deps")) then
                mod, path, key = fixedRequire(pathJoin(base, "deps", name))
                if mod then return mod, path, key end
              end
            end

            if base == "bundle:" then
              -- If we reach root of bundle, it doesn't exist
              break
            elseif base == "/" or base:byte(-1) == 58 then
              -- If we reach filesystem root, look in bundle
              base = "bundle:"
            else
              -- Otherwise, keep going higher
              base = pathJoin(base, "..")
            end
          end
        end


        local moduleCache = {}


        -- Prototype for module tables
        -- module.path - is path to module
        -- module.dir - is path to directory containing module
        -- module.exports - actual exports, initially is an empty table
        local Module = {}
        local moduleMeta = { __index = Module }

        local function makeModule(modulePath)
          -- Convert windows paths to unix paths (mostly)
          local path = modulePath:gsub("\\", "/")
          -- Normalize slashes around prefix to be exactly one after
          path = path:gsub("^/*([^/:]+:)/*", "%1/")
          return setmetatable({
            path = path,
            dir = pathJoin(path, ".."),
            exports = {}
          }, moduleMeta)
        end

        function Module:load(path)
          path = pathJoin(self.dir, './' .. path)
          local prefix = path:match("^bundle:/*")
          if prefix then
            return bundle.readfile(path:sub(#prefix + 1))
          end
          local fd, stat, data, err
          fd, err = uv.fs_open(path, "r", 511)
          if fd then
            stat, err = uv.fs_fstat(fd)
            if stat then
              data, err = uv.fs_read(fd, stat.size, -1)
            end
            uv.fs_close(fd)
          end
          if data then return data end
          return nil, err
        end

        function Module:scan(path)
          return scanDir(pathJoin(self.dir, './' .. path))
        end

        function Module:stat(path)
          return statFile(pathJoin(self.dir, './' .. path))
        end

        function Module:action(path, action)
          path = pathJoin(self.dir, './' .. path)
          local bundlePath = path:match("^bundle:/*(.*)")
          if bundlePath then
            return bundle.action(bundlePath, action)
          else
            return action(path)
          end
        end

        function Module:resolve(name)
          assert(name, "Missing name to resolve")
          local debundled_name = name:match("^bundle:(.*)") or name
          if debundled_name:byte(1) == 46 then -- Starts with "."
            return fixedRequire(pathJoin(self.dir, name))
          elseif debundled_name:byte(1) == 47 then -- Starts with "/"
            return fixedRequire(name)
          end
          return moduleRequire(self.dir, name)
        end

        function Module:require(name)
          assert(name, "Missing name to require")

          if package.preload[name] or package.loaded[name] then
            return realRequire(name)
          end

          -- Resolve the path
          local data, path, key = self:resolve(name)
          if not path then
            local success, value = pcall(realRequire, name)
            if success then return value end
            if not success then
              error("No such module '" .. name .. "' in '" .. self.path .. "'\r\n" ..  value)
            end
          end

          -- Check in the cache for this module
          local module = moduleCache[key]
          if module then return module.exports end
          -- Put a new module in the cache if not
          module = makeModule(path)
          moduleCache[key] = module

          local ext = path:match("%.[^/\\%.]+$")
          if ext == ".lua" then
            local match = path:match("^bundle:(.*)$")
            if match then
              local potential = pathJoin(bundle.base, "./" .. match)
              if uv.fs_access(potential, "r") then
                path = "@" .. potential
              end
            else
              path = "@" .. path
            end
            local fn = assert(loadstring(data, path))
            local global = {
              module = module,
              exports = module.exports,
              require = function (...)
                return module:require(...)
              end
            }
            setfenv(fn, setmetatable(global, { __index = _G }))
            local ret = fn()

            -- Allow returning the exports as well
            if ret then module.exports = ret end

          elseif ext == binExt then
            local fnName = "luaopen_" .. name:match("[^/]+$"):match("^[^%.]+")
            local fn, err
            local realPath = uv.fs_access(path, "r") and path or uv.fs_access(key, "r") and key
            if realPath then
              -- If it's a real file, load it directly
              fn, err = package.loadlib(realPath, fnName)
              if not fn then
                error(realPath .. "#" .. fnName .. ": " .. err)
              end
            else
              -- Otherwise, copy to a temporary folder and read from there
              local dir = assert(uv.fs_mkdtemp(pathJoin(tmpBase, "lib-XXXXXX")))
              path = pathJoin(dir, path:match("[^/\\]+$"))
              local fd = uv.fs_open(path, "w", 384) -- 0600
              uv.fs_write(fd, data, 0)
              uv.fs_close(fd)
              fn, err = package.loadlib(path, fnName)
              if not fn then
                error(path .. "#" .. fnName .. ": " .. err)
              end
              uv.fs_unlink(path)
              uv.fs_rmdir(dir)
            end
            module.exports = fn()
          else
            error("Unknown type at '" .. path .. "' for '" .. name .. "' in '" .. self.path .. "'")
          end
          return module.exports
        end


        local function generator(modulePath)
          assert(modulePath, "Missing path to require generator")

          local module = makeModule(modulePath)
          local function require(...)
            return module:require(...)
          end

          return require, module
        end

        return generator]])();
    local personalizedRequire = generator('//root//deps');
    return personalizedRequire(moduleName);
end;

local Utilities = {
	JSON = require'json';
	weblit = require'weblit';
	spawn = require'coro-spawn';
	parse = require'url'.parse;
};

local Server = {
	Active = false;
	Port = 4434; --make sure server is opened on this port
	Handler = nil;
	Host = '68.183.142.63';
	
	LastSpreadsheetArray = 'unset';
	
	GoogleAPI = '/GoogleSpreadsheetPHP/quickstart.php';
	Database = '/SpreadsheetJavaLuaServer/database';
	API = '/SpreadsheetJavaLuaServer/api-workspace';
};
local WebAPI = {};
local Extension = {};

Extension.FindArrayDifference = function(self, arr1, arr2)
		local nonequivalentIndexes = {};
		for i, v in next, arr1 do
				local arr2v = arr2[i];
				if (arr2v == nil) then
						if (arr2v ~= v and v:sub(1, 1) ~= '') then
								--[[local totalAscii = ;
								for i = 1, v:len() do
										totalAscii = totalAscii..string.byte(v:sub(i, i))..
								end;
								print(totalAscii);]]
								--print(arr2v, v);
								table.insert(nonequivalentIndexes, i);
						end;
				end;
		end;
		return nonequivalentIndexes;
end;

Extension.FilesInDirectory = function(self, directory)
    local i, t, popen = 0, {}, io.popen;
    local pfile = popen('ls -a "'..directory..'"');
    for filename in pfile:lines() do
        i = i + 1;
        t[i] = filename;
    end;
    pfile:close();
    return t;
end;

Extension.FilterArray = function(self, arr, filter)
	local newArray = {};
	for i, v in next, arr do
		if (filter(v) == true) then
			table.insert(newArray, v);
		end;
	end;
	return newArray;
end;

Extension.FileExists = function(self, directory)
	local file = io.open(directory, 'r');
	if (file ~= nil) then
		file:close();
		return true;
	end;
	return false;
end;

Extension.ValueExists = function(self, arr, val)
	for i, v in next, arr do
		if (v == val) then
			return true;
		end;
	end;
	return false;
end;

Extension.ExtractStartingQuery = function(self, url)
	local pos = {url:find('%?')};
	if (pos[1] ~= nil) then
		return url:sub(1, pos[1] - 1);
	end;
	return url;
end;

Extension.ReadAndCompress = function(self, directory)
	local existing = Extension:FileExists(directory);
	if (existing == true) then
		local lines = {};
		for l in io.lines(directory) do
			table.insert(lines, l);
		end;
		return table.concat(lines, '\n'), lines;
	end;
end;

Extension.Recompress = function(self, lines)
	local ls = {};
	for i, v in next, lines do
		ls[i] = v;
	end;
	return ls;
end;

Extension.ParseQuery = function(self, queryString)
	local parameters = {};
	for index, value in queryString:gmatch('([^&=?]-)=([^&=?]+)') do
		parameters[index] = value;
	end;
	return parameters;
end;

Extension.Encrypt = function(self, message, key)
	local key_bytes;
	if type(key) == 'string' then
		key_bytes = {};
		for key_index = 1, #key do
			key_bytes[key_index] = string.byte(key, key_index);
		end;
	else
		key_bytes = key;
	end;
	local message_length = #message;
	local key_length = #key_bytes;
	local message_bytes = {};
	for message_index = 1, message_length do
		message_bytes[message_index] = string.byte(message, message_index);
	end;
	local result_bytes = {};
	local random_seed = 0;
	for key_index = 1, key_length do
		random_seed = (random_seed + key_bytes[key_index] * key_index) * 1103515245 + 12345;
		random_seed = (random_seed - random_seed % 65536) / 65536 % 4294967296;
	end;
	for message_index = 1, message_length do
		local message_byte = message_bytes[message_index];
		for key_index = 1, key_length do
			local key_byte = key_bytes[key_index];
			local result_index = message_index + key_index - 1;
			local result_byte = message_byte + (result_bytes[result_index] or 0);
			if result_byte > 255 then
					result_byte = result_byte - 256;
			end;
			result_byte = result_byte + key_byte;
			if result_byte > 255 then
					result_byte = result_byte - 256;
			end;
			random_seed = (random_seed % 4194304 * 1103515245 + 12345);
			result_byte = result_byte + (random_seed - random_seed % 65536) / 65536 % 256;
			if result_byte > 255 then
				result_byte = result_byte - 256;
			end;
			result_bytes[result_index] = result_byte;
		end;
	end;
	local result_buffer = {};
	local result_buffer_index = 1;
	for result_index = 1, #result_bytes do
		local result_byte = result_bytes[result_index];
		result_buffer[result_buffer_index] = string.format('%02x', result_byte);
		result_buffer_index = result_buffer_index + 1;
	end;
	return table.concat(result_buffer);
end;
	
Extension.Decrypt = function(self, cipher, key)
	local key_bytes;
	if type(key) == 'string' then
		key_bytes = {};
		for key_index = 1, #key do
			key_bytes[key_index] = string.byte(key, key_index);
		end;
	else
		key_bytes = key;
	end;
	local cipher_raw_length = #cipher;
	local key_length = #key_bytes;
	local cipher_bytes = {};
	local cipher_length = 0;
	local cipher_bytes_index = 1;
	for byte_str in string.gmatch(cipher, '%x%x') do
		cipher_length = cipher_length + 1;
		cipher_bytes[cipher_length] = tonumber(byte_str, 16);
	end;
	local random_bytes = {};
	local random_seed = 0;
	for key_index = 1, key_length do
		random_seed = (random_seed + key_bytes[key_index] * key_index) * 1103515245 + 12345;
		random_seed = (random_seed - random_seed % 65536) / 65536 % 4294967296;
	end;
	for random_index = 1, (cipher_length - key_length + 1) * key_length do
		random_seed = (random_seed % 4194304 * 1103515245 + 12345);
		random_bytes[random_index] = (random_seed - random_seed % 65536) / 65536 % 256;
	end;
	local random_index = #random_bytes;
	local last_key_byte = key_bytes[key_length];
	local result_bytes = {};
	for cipher_index = cipher_length, key_length, -1 do
		local result_byte = cipher_bytes[cipher_index] - last_key_byte;
		if result_byte < 0 then
			result_byte = result_byte + 256;
		end;
		result_byte = result_byte - random_bytes[random_index];
		random_index = random_index - 1;
		if result_byte < 0 then
			result_byte = result_byte + 256;
		end;
		for key_index = key_length - 1, 1, -1 do
			cipher_index = cipher_index - 1;
			local cipher_byte = cipher_bytes[cipher_index] - key_bytes[key_index];
			if cipher_byte < 0 then
				cipher_byte = cipher_byte + 256;
			end;
			cipher_byte = cipher_byte - result_byte;
			if cipher_byte < 0 then
				cipher_byte = cipher_byte + 256;
			end;
			cipher_byte = cipher_byte - random_bytes[random_index];
			random_index = random_index - 1;
			if cipher_byte < 0 then
				cipher_byte = cipher_byte + 256;
			end;
			cipher_bytes[cipher_index] = cipher_byte;
		end;
		result_bytes[cipher_index] = result_byte;
	end;
	local result_characters = {};
	for result_index = 1, #result_bytes do
		result_characters[result_index] = string.char(result_bytes[result_index]);
	end;
	return table.concat(result_characters);
end;

local Database = {};
Database.Key = 'BGCL';
Database.CacheSession = {};
Database.list = function(self)
	local Files = Extension:FilesInDirectory(Server.Database);
	local ls = {};
	for i, v in next, Files do
		if (v ~= '..' and v ~= '.') then
			ls[v] = Server.Database..'/'..v;
		end;
	end;
	return ls;
end;
Database.exists = function(self, name)
	return self:list()[name];
end;
Database.new = function(self, name)
	if (self:exists(name) == nil) then
		local db_file = io.open(Server.Database..'/'..name, 'w+');
		db_file:write(Extension:Encrypt(Utilities.JSON.encode({}), self.Key));
		db_file:close();
	end;
	return self:wrap(name);
end;
Database.wrap = function(self, name)
	local Databases = self:list();
	assert(Databases[name] ~= nil, 'Database '..name..' cannot be found');
	local DatabaseDirectory = Databases[name];
	assert(DatabaseDirectory:find('.edd') ~= nil, 'File type not supported');
	if (self.CacheSession[name] ~= nil) then --reduce memory usage
		return self.CacheSession[name];
	end;
	local GetBody = function()
		local File = io.open(DatabaseDirectory, 'r+');
		local Body = File:read('*all');
		if (Body == '' or Body == '\n') then
			Body = Extension:Encrypt('[]', self.Key);
		end;
		File:close();
		return Body;
	end;
	local SetBody = function(index, value)
		local Body = GetBody();
		local Database = Utilities.JSON.decode(Extension:Decrypt(Body, self.Key));
		Database[index] = value;
		local File = io.open(DatabaseDirectory, 'w+');
		File:write(Extension:Encrypt(Utilities.JSON.encode(Database), self.Key));
		File:close();
	end;
	
	local PureObject = newproxy(true);
	local Mod = getmetatable(PureObject);
	Mod.__index = function(self, index)
		if (index == 'list') then
			local Body = GetBody();
			return Utilities.JSON.decode(Extension:Decrypt(Body, Database.Key));
		else
			local Body = GetBody();
			local Db = Utilities.JSON.decode(Extension:Decrypt(Body, Database.Key));
			return Db[index];
		end;
	end;
	Mod.__newindex = function(self, index, value)
		SetBody(index, value);
	end;
	Mod.__tostring = function() return name; end;
	Mod.__directory = DatabaseDirectory;
	self.CacheSession[name] = PureObject;
	return PureObject;
end;

--This could either be my server constantly checking the cells on the spreadsheet, or:
--We could create a C++ application to find out when something in excel is pasted, and we can use a flask server to check and apply data.
 
local wait = function(s)
	local start = os.time();
	repeat until (os.time() - start) >= s;
	return os.time() - start;
end;

while (wait(5)) do
		print'Checking...';
		local SheetId = '1OnApSQ09shaZ06TriU0l7BAa_wf8KpJ_m2Eyevk02kc';
		local SheetName = 'Sheet1';
    local File = io.popen('cd '..Server.GoogleAPI:gsub('/quickstart.php', '')..' && php quickstart.php gr '..SheetName..' A1:A '..SheetId);
    local Output = File:read('*all');
    File:close();
    local SpreadsheetData = Utilities.JSON.decode(Output) or {{};};
		local ColumnA = SpreadsheetData[1];
		local LastValueCriticalPts = (function()
				if (Server.LastSpreadsheetArray == 'unset') then
						return 'unset';
				end;
				return #Server.LastSpreadsheetArray[1];
		end)();
		local ValueCriticalPoints = #ColumnA;
		if (type(LastValueCriticalPts):lower() == 'number') then
				--need to check for change
				--If your current critical points are greater than the cache critical points, then something was added
				--However if your current critical points are lesser than the cache critical points, most likely something was removed
				--we want to check even if the values are the same, implying that it hasn't changed
				--we check it because we need to test these critical points, like we do in calculus to determine if they're true critical points.
				if (ValueCriticalPoints >= LastValueCriticalPts) then
						local Differences = Extension:FindArrayDifference(ColumnA, Server.LastSpreadsheetArray[1]);
						if (#Differences >= 1) then
								for i, v in next, Differences do --v is also the row index
										local NewChange = ColumnA[v]; --difference inside our updated Column A1
										print('GOT CHANGE:', NewChange);
										local lineSearch = nil;
										local currentIndex = 0;
										for line in io.lines('/GoogleSpreadsheetPHP/batman.csv') do
												currentIndex = currentIndex + 1;
												if (line:find(NewChange) ~= nil) then
														lineSearch = line;
														break;
												end;
										end;
										if (lineSearch == nil) then
												currentIndex = 'NONE';
										end;
										if (lineSearch ~= nil) then
												local File = io.popen('cd '..Server.GoogleAPI:gsub('/quickstart.php', '')..' && php quickstart.php ec '..SheetName..' NONE '..SheetId..' '..v..' '..currentIndex);
    										File:close();
										end;
								end;
						end;
				end;
		end;
		Server.LastSpreadsheetArray = SpreadsheetData;
end;

if (Server.Active == true) then
	Server.Handler = Utilities.weblit.app.bind{host = Server.Host, port = Server.Port}
	.use(require('weblit-auto-headers'))
	.use(require('weblit-logger'))
	.use(function (req, res, go)
		local directoryPath = req.path;
		local fixedPath = Extension:ExtractStartingQuery(directoryPath:gsub('%.%.', ''));
		local functionExists = Extension:FileExists(Server.API..fixedPath);
		local parsedUrl = Utilities.parse(directoryPath);
		local queryString = parsedUrl.search;
		local query = Extension:ParseQuery(queryString or '');
		if (functionExists == true) then
			local fileBody, bodyLines = Extension:ReadAndCompress(Server.API..fixedPath);
			local methodHeader = bodyLines[1];
			assert(methodHeader:sub(1, 1) == '#', 'Method Header not found');
			local wantedMethod = methodHeader:gsub('#', '');
			if (req.method == wantedMethod) then
				local apiInit = loadstring(table.concat(bodyLines, '\n', 2));
				local ran, result = pcall(function() --bot_api, params, post
					return setfenv(apiInit, env)(WebAPI, query, req.body);
				end);
				if (not ran) then
					res.headers['Connection'] = 'Close';
					res.code = 404;
		    		res.body = 'An error has occured';
				else
					res.code = 200;
					res.body = result or 'API did not return anything';
				end;
				return go();
			end;
			--res.headers["Content-Type"] = "text/html"
			--this is a fucking api not a website so we won't auto redirect to index.html
		end;
		res.headers['Connection'] = 'Close';
		res.code = 404;
		res.body = 'Not found';
		return go();
	end)
	.start();
end;
