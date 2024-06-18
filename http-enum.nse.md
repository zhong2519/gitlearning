# http-enum.nse

这个Nmap NSE脚本的主要功能是枚举HTTP服务器上常见的目录和文件，并尝试识别服务器使用的Web应用程序和版本。它通过发送HTTP请求，根据预定义的指纹数据库匹配响应，来发现可能存在的敏感文件或目录。

关键功能

	1.	端口规则（portrule）：
	•	指定脚本适用于HTTP服务的端口（通常是80和443）。
	2.	辅助函数：
	•	get_fingerprints 函数：从指纹文件中读取和解析指纹数据，并验证其有效性。
	•	bad_prints 函数：处理指纹文件读取错误，记录错误信息并解锁互斥锁。
	•	get_variations函数：
	3.	action 部分：
	•	读取脚本参数：读取用户提供的参数，或使用默认值。
	•	读取并解析指纹文件：调用get_fingerprints函数，获取指纹数据。
	•	识别无效HTTP请求：检查服务器是否对所有请求返回200状态码，以确定是否继续进行测试。
	•	准备和发送HTTP请求：根据指纹文件生成请求，并使用管道发送多个HTTP请求。
	•	处理响应结果：根据响应内容匹配指纹，识别有效的目录和文件，并记录结果。



## 头部信息

##### 1.导入模块

```
local _G = require "_G": 引入全局环境库。
local http = require "http": 引入HTTP库，用于处理HTTP请求。
local nmap = require "nmap": 引入Nmap库，提供Nmap的核心功能。
local shortport = require "shortport": 引入shortport库，用于端口规则匹配。
local stdnse = require "stdnse": 引入标准NSE库，提供NSE脚本的标准函数。
local string = require "string": 引入字符串处理库。
local table = require "table": 引入表处理库。
```

##### 2.description字段

```
description = [[
Enumerates directories used by popular web applications and servers.
枚举流行的Web应用程序和服务器使用的目录。

This parses a fingerprint file that's similar in format to the Nikto Web application
scanner. This script, however, takes it one step further by building in advanced pattern matching as well
as having the ability to identify specific versions of Web applications.
该脚本解析一个类似于Nikto Web应用程序扫描器格式的指纹文件。然而，这个脚本更进一步，内置了高级模式匹配功能，并具有识别特定Web应用程序版本的能力。

You can also parse a Nikto-formatted database using http-fingerprints.nikto-db-path. This will try to parse
most of the fingerprints defined in nikto's database in real time. More documentation about this in the
nselib/data/http-fingerprints.lua file.
你也可以使用http-fingerprints.nikto-db-path参数解析Nikto格式的数据库。这将尝试实时解析Nikto数据库中定义的大部分指纹。更多文档可以在nselib/data/http-fingerprints.lua文件中找到。

Currently, the database can be found under Nmap's directory in the nselib/data folder. The file is called
http-fingerprints and has a long description of its functionality in the file header.
目前，数据库可以在Nmap目录下的nselib/data文件夹中找到。该文件名为http-fingerprints，并在文件头中有其功能的详细描述。

Many of the finger prints were discovered by me (Ron Bowes), and a number of them are from the Yokoso
project, used with permission from Kevin Johnson (http://seclists.org/nmap-dev/2009/q3/0685.html).

Initially, this script attempts to access two different random files in order to detect servers
that don't return a proper 404 Not Found status. In the event that they return 200 OK, the body
has any non-static-looking data removed (URI, time, etc), and saved. If the two random attempts
return different results, the script aborts (since a 200-looking 404 cannot be distinguished from
an actual 200). This will prevent most false positives.
最初，该脚本尝试访问两个不同的随机文件，以检测那些不返回正确404 Not Found状态的服务器。如果它们返回200 OK，主体中的任何非静态数据（如URI、时间等）将被移除并保存。如果两次随机尝试返回不同的结果，脚本会中止（因为无法区分200-looking 404和实际的200）。这将防止大多数误报。

In addition, if the root folder returns a 301 Moved Permanently or 401 Authentication Required,
this script will also abort. If the root folder has disappeared or requires authentication, there
is little hope of finding anything inside it.
此外，如果根文件夹返回301 Moved Permanently或401 Authentication Required，该脚本也会中止。如果根文件夹消失或需要身份验证，那么在其内部找到任何东西的希望都很小。

By default, only pages that return 200 OK or 401 Authentication Required are displayed. If the
<code>http-enum.displayall</code> script argument is set, however, then all results will be displayed (except
for 404 Not Found and the status code returned by the random files). Entries in the http-fingerprints
database can specify their own criteria for accepting a page as valid.
默认情况下，只显示返回200 OK或401 Authentication Required的页面。如果设置了http-enum.displayall脚本参数，则会显示所有结果（除了404 Not Found和随机文件返回的状态代码）。http-fingerprints数据库中的条目可以指定它们自己的页面有效性标准。
]]
```

##### 3.NSEDoc、author、license、categories

```
---
-- @args http-enum.basepath         The base path to prepend to each request. Leading/trailing slashes are ignored.
-- @args http-enum.displayall       Set this argument to display all status codes that may indicate a valid page, not
--                                  just 200 OK and 401 Authentication Required pages. Although this is more likely
--                                  to find certain hidden folders, it also generates far more false positives.
-- @args http-enum.fingerprintfile  Specify a different file to read fingerprints from.
-- @args http-enum.category         Set to a category (as defined in the fingerprints file). Some options are 'attacks',
--                                  'database', 'general', 'microsoft', 'printer', etc.
-- @args http-fingerprints.nikto-db-path Looks at the given path for nikto database.
--       It then converts the records in nikto's database into our Lua table format
--       and adds them to our current fingerprints if they don't exist already.
--       Unfortunately, our current implementation has some limitations:
--          * It doesn't support records with more than one 'dontmatch' patterns for
--            a probe.
--          * It doesn't support logical AND for the 'match' patterns.
--          * It doesn't support sending additional headers for a probe.
--       That means, if a nikto fingerprint needs one of the above features, it
--       won't be loaded. At the time of writing this, 6546 out of the 6573 Nikto
--       fingerprints are being loaded successfully.  This runtime Nikto fingerprint integration was suggested by Nikto co-author Chris Sullo as described at http://seclists.org/nmap-dev/2013/q4/292
--
-- @output
-- Interesting ports on test.skullsecurity.org (208.81.2.52):
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-enum:
-- |   /icons/: Icons and images
-- |   /images/: Icons and images
-- |   /robots.txt: Robots file
-- |   /sw/auth/login.aspx: Citrix WebTop
-- |   /images/outlook.jpg: Outlook Web Access
-- |   /nfservlets/servlet/SPSRouterServlet/: netForensics
-- |_  /nfservlets/servlet/SPSRouterServlet/: netForensics
--
-- @see http-iis-short-name-brute.nse

author = {"Ron Bowes", "Andrew Orr", "Rob Nicholls"}

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "intrusive", "vuln"}
```



脚本参数（@args）

	1.	http-enum.basepath：
		•	描述：在每个请求前添加一个基路径。忽略前导和尾随斜杠。
		•	来源：通过命令行参数设置，用于指定HTTP请求的基础路径。
		•	示例：nmap --script=http-enum --script-args=http-enum.basepath=/admin
	2.	http-enum.displayall：
		•	描述：设置此参数以显示所有可能指示有效页面的状态代码，而不仅仅是200 OK和401 Authentication Required页面。虽然这更有可能找到隐藏的文件夹，但也会产生更多的误报。
		•	来源：通过命令行参数设置，控制脚本输出的详细程度。
		•	示例：nmap --script=http-enum --script-args=http-enum.displayall=true
	3.	http-enum.fingerprintfile：
		•	描述：指定一个不同的文件来读取指纹信息。
		•	来源：通过命令行参数设置，用于指定自定义的指纹文件路径。
		•	示例：nmap --script=http-enum --script-args=http-enum.fingerprintfile=/path/to/fingerprints
	4.	http-enum.category：
		•	描述：设置为指纹文件中定义的类别之一。例如：“attacks”、“database”、“general”、“microsoft”、“printer”等。
		•	来源：通过命令行参数设置，用于选择特定类别的指纹进行枚举。
		•	示例：nmap --script=http-enum --script-args=http-enum.category=general
	5.	http-fingerprints.nikto-db-path：
		•	描述：查看给定路径中的Nikto数据库。然后将Nikto数据库中的记录转换为Lua表格式，并将它们添加到当前的指纹中（如果它们尚不存在）。
		•	来源：通过命令行参数设置，用于指定Nikto数据库的路径。
		•	示例：nmap --script=http-enum --script-args=http-fingerprints.nikto-db-path=/path/to/nikto/db



脚本输出（@output）：示例输出展示了对目标服务器上的一些有趣端口和路径的枚举结果

```
1.  头部信息：
   •	Interesting ports on test.skullsecurity.org (208.81.2.52): 表示目标主机的域名和IP地址。
   •	PORT   STATE SERVICE REASON: 标题行，表示后续列出的分别是端口、状态、服务和原因。
2.	端口信息：
   •	80/tcp open  http    syn-ack:
   •	80/tcp: 端口号和协议类型（这里是TCP协议的80端口）。
   •	open: 端口状态，表示该端口是打开的。
   •	http: 服务名称，表示该端口运行的是HTTP服务。
   •	syn-ack: 表示探测到端口开放的原因，这里是通过SYN-ACK确认端口开放。
3.	脚本输出：
   •	| http-enum:: 脚本名称，表示以下内容是http-enum脚本的输出。
   •	逐行列出脚本发现的目录和文件：
   •	/icons/: Icons and images: 表示在目标服务器的/icons/路径下发现了图标和图像文件。
   •	/images/: Icons and images: 表示在/images/路径下也发现了图标和图像文件。
   •	/robots.txt: Robots file: 表示在根目录下发现了robots.txt文件，通常用于指示搜索引擎爬虫哪些页面不应被抓取。
   •	/sw/auth/login.aspx: Citrix WebTop: 表示在/sw/auth/login.aspx路径下发现了Citrix WebTop应用程序的登录页面。
   •	/images/outlook.jpg: Outlook Web Access: 表示在/images/outlook.jpg路径下发现了与Outlook Web Access相关的图像文件。
   •	/nfservlets/servlet/SPSRouterServlet/: netForensics: 表示在/nfservlets/servlet/SPSRouterServlet/路径下发现了与netForensics相关的内容。
```



其他信息

	•	@see 标签引用了相关的NSE脚本，供进一步参考。
	•	作者：列出了编写和维护该脚本的作者。
	•	许可证：脚本遵循与Nmap相同的许可协议。
	•	类别：脚本被归类为“discovery”、“intrusive”和“vuln”，即发现、侵入和漏洞类别。



## portrule 部分

```
portrule = shortport.http

-- TODO
-- o Automatically convert HEAD -> GET if the server doesn't support HEAD
-- o Add variables for common extensions, common CGI extensions, etc that expand the probes

-- File extensions (TODO: Implement this)
local cgi_ext = { 'php', 'asp', 'aspx', 'jsp', 'pl', 'cgi' }

local common_ext = { 'php', 'asp', 'aspx', 'jsp', 'pl', 'cgi', 'css', 'js', 'htm', 'html' }

---Convert the filename to backup variations. These can be valuable for a number of reasons.
-- First, because they may not have the same access restrictions as the main version (file.php
-- may run as a script, but file.php.bak or file.php~ might not). And second, the old versions
-- might contain old vulnerabilities
--
-- At the time of the writing, these were all decided by me (Ron Bowes).
```

1. 端口规则（portrule）：
   •	portrule = shortport.http: 这个规则定义了脚本适用于哪些端口。这里使用shortport.http表示脚本适用于HTTP服务的端口（通常是80和443）。

2. TODO注释：
   •	脚本作者在TODO注释中列出了一些**未来可能需要实现**的功能：
        •	自动将不支持HEAD请求的服务器转换为GET请求。
        •	为常见扩展名和CGI扩展名添加变量，以扩展探测。

3. 文件扩展名列表：
   •	local cgi_ext和local common_ext定义了一些常见的CGI和文件扩展名，这些可以在探测过程中使用。

   

## 辅助函数

#### get_variations函数

```
local function get_variations(filename)
  local variations = {}
  
  if(filename == nil or filename == "" or filename == "/") then
    return {}
  end

  local is_directory = (string.sub(filename, #filename, #filename) == "/")
  if(is_directory) then
    filename = string.sub(filename, 1, #filename - 1)
  end

  -- Try some extensions
  table.insert(variations, filename .. ".bak")
  table.insert(variations, filename .. ".1")
  table.insert(variations, filename .. ".tmp")

  -- Strip off the extension, if it has one, and try it all again.
  -- For now, just look for three-character extensions.
  if(string.sub(filename, #filename - 3, #filename - 3) == '.') then
    local bare = string.sub(filename, 1, #filename - 4)
    local extension = string.sub(filename, #filename - 3)

    table.insert(variations, bare .. ".bak")
    table.insert(variations, bare .. ".1")
    table.insert(variations, bare .. ".tmp")
    table.insert(variations, bare .. "_1" .. extension)
    table.insert(variations, bare .. "2" .. extension)
  end


  -- Some Windowsy things
  local onlyname = string.sub(filename, 2)
  -- If the name contains a '/', forget it
  if(string.find(onlyname, "/") == nil) then
    table.insert(variations, "/Copy of " .. onlyname)
    table.insert(variations, "/Copy (2) of " .. onlyname)
    table.insert(variations, "/Copy of Copy of " .. onlyname)

    -- Word/Excel/etc replace the first two characters with '~$', it seems
    table.insert(variations, "/~$" .. string.sub(filename, 4))
  end

  -- Some editors add a '~'
  table.insert(variations, filename .. "~")

  -- Try some directories
  table.insert(variations, "/bak" .. filename)
  table.insert(variations, "/backup" .. filename)
  table.insert(variations, "/backups" .. filename)
  table.insert(variations, "/beta" .. filename)
  table.insert(variations, "/test" .. filename)

  -- If it's a directory, add a '/' after every entry
  if(is_directory) then
    for i, v in ipairs(variations) do
      variations[i] = v .. "/"
    end
  end

  -- Some compressed formats (we don't want a trailing '/' on these, so they go after the loop)
  table.insert(variations, filename .. ".zip")
  table.insert(variations, filename .. ".tar")
  table.insert(variations, filename .. ".tar.gz")
  table.insert(variations, filename .. ".tgz")
  table.insert(variations, filename .. ".tar.bz2")



  return variations
end
```

get_variations函数：

•	get_variations函数生成了给定文件名的多种变体，帮助在安全测试中发现备份文件和目录。
•	这些变体包括常见的备份扩展名、Windows系统变体、编辑器变体、目录变体和压缩格式。



#### bad_prints函数

```
-- simplify unlocking the mutex, ensuring we don't try to parse again, and returning an error.
local function bad_prints(mutex, err)
  nmap.registry.http_fingerprints = err
  mutex "done"
  return false, err
end
```

1. 函数定义：
   •	local function bad_prints(mutex, err)：定义一个名为bad_prints的局部函数，接受两个参数：mutex和err。

2.	Nmap注册表：
•	nmap.registry.http_fingerprints = err：将错误信息err存储到Nmap的注册表中。Nmap的注册表是一个全局Lua表，所有脚本都可以访问，用于存储共享数据。在这里，http_fingerprints键被设置为错误信息err。
3.	解锁互斥锁：
•	mutex "done"：调用mutex函数并传递字符串"done"，这表示互斥锁操作已完成。互斥锁用于同步脚本中的并发操作，确保同一时间只有一个线程在处理特定操作。在这里，解锁互斥锁以避免其他线程再次尝试解析。
4.	返回值：
•	return false, err：函数返回两个值：false和错误信息err。返回false表示操作失败，并伴随错误信息。

这段代码的作用是简化错误处理过程，特别是在解析HTTP指纹文件时发生错误的情况下。具体功能包括：

	1.	记录错误：将错误信息记录到Nmap的全局注册表中，供其他脚本或操作使用。
	2.	解锁互斥锁：确保在发生错误时正确解锁互斥锁，以避免资源锁定或死锁。
	3.	返回错误信息：返回操作失败标志和错误信息，以便调用者可以根据错误信息采取适当的措施。



#### get_fingerprints函数

其作用是从文件中读取和解析HTTP指纹信息，并根据需要进行验证和过滤。

##### 函数头部及参数

```
---Get the list of fingerprints from files. The files are defined in <code>fingerprint_files</code>. If category
-- is non-nil, only choose scripts that are in that category.
--
--@return An array of entries, each of which have a <code>checkdir</code> field, and possibly a <code>checkdesc</code>.
local function get_fingerprints(fingerprint_file, category)
  local entries  = {}
  local i
  local total_count = 0 -- Used for 'limit'
```

•	函数定义：定义一个名为get_fingerprints的局部函数，接受两个参数fingerprint_file和category。
•	局部变量：初始化一些局部变量，如entries（用于存储指纹条目）、i和total_count（用于计数）。



##### 检查并锁定互斥锁

```
  -- Check if we've already read the file
  local mutex = nmap.mutex("http_fingerprints")
  mutex "lock"
  if nmap.registry.http_fingerprints then
    if type(nmap.registry.http_fingerprints) == "table" then
      stdnse.debug1("Using cached HTTP fingerprints")
      mutex "done"
      return true, nmap.registry.http_fingerprints
    else
      return bad_prints(mutex, nmap.registry.http_fingerprints)
    end
  end
```

- **检查缓存**：检查是否已经读取了指纹文件。如果指纹信息已经存在于Nmap的注册表中，则使用缓存的数据。
- **互斥锁**：使用互斥锁`http_fingerprints`来确保线程安全。锁定互斥锁以防止其他线程同时访问。
- **返回缓存数据**：如果指纹信息已缓存且类型为表，返回缓存的数据。否则，调用`bad_prints`函数处理错误。



##### 查找并加载指纹文件

```
  -- Try and find the file; if it isn't in Nmap's directories, take it as a direct path
  local filename_full = nmap.fetchfile('nselib/data/' .. fingerprint_file)
  if(not(filename_full)) then
    filename_full = fingerprint_file
  end

  stdnse.debug1("Loading fingerprint database: %s", filename_full)
  local env = setmetatable({fingerprints = {}}, {__index = _G})
  local file = loadfile(filename_full, "t", env)
  if(not(file)) then
    stdnse.debug1("Couldn't load configuration file: %s", filename_full)
    return bad_prints(mutex, "Couldn't load fingerprint file: " .. filename_full)
  end

  file()
```

- **查找文件**：尝试在Nmap目录中查找指纹文件。如果找不到，则使用直接路径。
- **加载文件**：使用`loadfile`加载指纹文件，并设置一个带有`fingerprints`字段的环境表。调用加载的文件，将指纹数据填充到环境表中。



##### 验证指纹数据

```
  local fingerprints = env.fingerprints

  -- Sanity check our file to ensure that all the fields were good. If any are bad, we
  -- stop and don't load the file.
  for i, fingerprint in pairs(fingerprints) do
    -- Make sure we have a valid index
    if(type(i) ~= 'number') then
      return bad_prints(mutex, "The 'fingerprints' table is an array, not a table; all indexes should be numeric")
    end

    -- Make sure they have either a string or a table of probes
    if(not(fingerprint.probes) or
        (type(fingerprint.probes) ~= 'table' and type(fingerprint.probes) ~= 'string') or
        (type(fingerprint.probes) == 'table' and #fingerprint.probes == 0)) then
      return bad_prints(mutex, "Invalid path found for fingerprint " .. i)
    end

    -- Make sure fingerprint.path is a table
    if(type(fingerprint.probes) == 'string') then
      fingerprint.probes = {fingerprint.probes}
    end

    -- Make sure the elements in the probes array are strings or arrays
    for i, probe in pairs(fingerprint.probes) do
      -- Make sure we have a valid index
      if(type(i) ~= 'number') then
        return bad_prints(mutex, "The 'probes' table is an array, not a table; all indexes should be numeric")
      end

      -- Convert the probe to a table if it's a string
      if(type(probe) == 'string') then
        fingerprint.probes[i] = {path=fingerprint.probes[i]}
        probe = fingerprint.probes[i]
      end

      -- Make sure the probes table has a 'path'
      if(not(probe['path'])) then
        return bad_prints(mutex, "The 'probes' table requires each element to have a 'path'.")
      end

      -- If they didn't set a method, set it to 'GET'
      if(not(probe['method'])) then
        probe['method'] = 'GET'
      end

      -- Make sure the method's a string
      if(type(probe['method']) ~= 'string') then
        return bad_prints(mutex, "The 'method' in the probes file has to be a string")
      end
    end

    -- Ensure that matches is an array
    if(type(fingerprint.matches) ~= 'table') then
      return bad_prints(mutex, "'matches' field has to be a table")
    end

    -- Loop through the matches
    for i, match in pairs(fingerprint.matches) do
      -- Make sure we have a valid index
      if(type(i) ~= 'number') then
        return bad_prints(mutex, "The 'matches' table is an array, not a table; all indexes should be numeric")
      end

      -- Check that every element in the table is an array
      if(type(match) ~= 'table') then
        return bad_prints(mutex, "Every element of 'matches' field has to be a table")
      end

      -- Check the output field
      if(match['output'] == nil or type(match['output']) ~= 'string') then
        return bad_prints(mutex, "The 'output' field in 'matches' has to be present and a string")
      end

      -- Check the 'match' and 'dontmatch' fields, if present
      if((match['match'] and type(match['match']) ~= 'string') or (match['dontmatch'] and type(match['dontmatch']) ~= 'string')) then
        return bad_prints(mutex, "The 'match' and 'dontmatch' fields in 'matches' have to be strings, if they exist")
      end

      -- Change blank 'match' strings to '.*' so they match everything
      if(not(match['match']) or match['match'] == '') then
        match['match'] = '(.*)'
      end
    end

    -- Make sure the severity is an integer between 1 and 4. Default it to 1.
    if(fingerprint.severity and (type(fingerprint.severity) ~= 'number' or fingerprint.severity < 1 or fingerprint.severity > 4)) then
      return bad_prints(mutex, "The 'severity' field has to be an integer between 1 and 4")
    elseif not fingerprint.severity then
      fingerprint.severity = 1
    end

    -- Make sure ignore_404 is a boolean. Default it to false.
    if(fingerprint.ignore_404 and type(fingerprint.ignore_404) ~= 'boolean') then
      return bad_prints(mutex, "The 'ignore_404' field has to be a boolean")
    elseif not fingerprint.ignore_404 then
      fingerprint.ignore_404 = false
    end
  end

  -- Make sure we have some fingerprints
  if(#fingerprints == 0) then
    return bad_prints(mutex, "No fingerprints were loaded")
  end
```

**检查指纹**：遍历指纹数据，确保每个指纹的各个字段有效。

**检查索引**：确保指纹表的索引是数字。

**检查探测字段**：确保探测字段存在且为字符串或表，并将字符串转换为表。

**检查匹配字段**：确保匹配字段存在且为表，检查各个子字段的有效性。

**检查严重性字段**：确保严重性字段为1到4之间的整数，默认设置为1。

**检查忽略404字段**：确保忽略404字段为布尔值，默认设置为false。



##### 过滤和缓存指纹数据

```
  -- If the user wanted to filter by category, do it
  if(category) then
    local filtered_fingerprints = {}
    for _, fingerprint in pairs(fingerprints) do
      if(fingerprint.category == category) then
        table.insert(filtered_fingerprints, fingerprint)
      end
    end

    fingerprints = filtered_fingerprints

    -- Make sure we still have fingerprints after the category filter
    if(#fingerprints == 0) then
      return bad_prints(mutex, "No fingerprints matched the given category (" .. category .. ")")
    end
  end


  --  -- If the user wants to try variations, add them
  --  if(try_variations) then
  --    -- Get a list of all variations for this directory
  --    local variations = get_variations(entry['checkdir'])
  --
  --    -- Make a copy of the entry for each of them
  --    for _, variation in ipairs(variations) do
  --      new_entry = {}
  --      for k, v in pairs(entry) do
  --        new_entry[k] = v
  --      end
  --      new_entry['checkdesc'] = new_entry['checkdesc'] .. " (variation)"
  --      new_entry['checkdir'] = variation
  --      table.insert(entries, new_entry)
  --      count = count + 1
  --    end
  --  end

  -- Cache the fingerprints for other scripts, so we aren't reading the files every time
  nmap.registry.http_fingerprints = fingerprints
  mutex "done"

  return true, fingerprints
end
```

- **按类别过滤**：如果提供了类别参数，过滤指纹数据只保留匹配的类别。
- **缓存指纹数据**：将指纹数据存储到Nmap的注册表中，以便其他脚本可以使用缓存的数据。
- **释放互斥锁**：解锁互斥锁，表示操作完成。
- **返回结果**：返回操作成功标志和指纹数据。



## action部分

#### 函数头部及参数读取

```
action = function(host, port)
  local response = {}

  -- 读取脚本参数
  local basepath         = stdnse.get_script_args({'http-enum.basepath',        'path'})         or '/'
  local displayall       = stdnse.get_script_args({'http-enum.displayall',      'displayall'})   or false
  local fingerprint_file = stdnse.get_script_args({'http-enum.fingerprintfile', 'fingerprints'}) or 'http-fingerprints.lua'
  local category         = stdnse.get_script_args('http-enum.category')
  --  local try_variations   = stdnse.get_script_args({'http-enum.tryvariations',   'variations'})   or false
  --  local limit            = tonumber(stdnse.get_script_args({'http-enum.limit', 'limit'})) or -1

```

- **读取脚本参数**：通过`stdnse.get_script_args`函数读取脚本运行时传递的参数，如果没有提供参数则使用默认值。



#### 读取并解析指纹文件

```
  -- 从外部文件中添加URL
  local status, fingerprints = get_fingerprints(fingerprint_file, category)
  if not status then
    return stdnse.format_output(false, fingerprints)
  end
  stdnse.debug1("Loaded %d fingerprints", #fingerprints)

```

- **调用`get_fingerprints`函数**：读取并解析指纹文件。如果读取失败，则返回错误信息。



····························省略······························

## 总结

1.	端口规则（portrule）：
	•	指定脚本适用于HTTP服务的端口（通常是80和443）。
1.	辅助函数：
	•	get_fingerprints 函数：从指纹文件中读取和解析指纹数据，并验证其有效性。
	•	bad_prints 函数：处理指纹文件读取错误，记录错误信息并解锁互斥锁。
	•	get_variations 函数：生成文件名的多种备份变体，帮助在安全测试中发现可能未被注意的备份文件和目录。
1.	action 部分：
	•	读取脚本参数：读取用户提供的参数，或使用默认值。
	•	读取并解析指纹文件：调用 get_fingerprints 函数，获取指纹数据。
	•	识别无效HTTP请求：检查服务器是否对所有请求返回200状态码，以确定是否继续进行测试。
	•	准备和发送HTTP请求：根据指纹文件生成请求，并使用管道发送多个HTTP请求。
	•	处理响应结果：根据响应内容匹配指纹，识别有效的目录和文件，并记录结果。



这个Nmap NSE脚本通过读取指纹数据库，生成多种HTTP请求，并分析服务器的响应，来识别和枚举HTTP服务器上的常见目录和文件。定义了辅助函数 get_fingerprints、bad_prints 和 get_variations，这些函数帮助脚本更有效地执行其任务，确保脚本可以读取和解析指纹文件，处理错误，生成文件名变体，并最终将结果返回给用户。
