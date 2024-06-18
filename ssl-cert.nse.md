# ssl-cert脚本

### 导入模块

```
local datetime = require "datetime"
local nmap = require "nmap"
local outlib = require "outlib"
local shortport = require "shortport"
local sslcert = require "sslcert"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"
local unicode = require "unicode"
local have_openssl, openssl = pcall(require, "openssl")
```

模块作用

1. **datetime**：用于处理和格式化日期和时间。

2. **nmap**：提供与Nmap工具相关的函数和对象，允许脚本访问Nmap的功能。

3. **outlib**：用于输出格式化和处理输出数据。

4. **shortport**：用于简化端口规则的定义，帮助脚本确定在哪些端口运行。

5. **sslcert**：专门用于处理SSL证书的库，提供解析和处理证书的功能。

6. **stdnse**：NSE脚本的标准库，提供了各种辅助函数和实用工具。

7. **string** 和 **table**：Lua标准库，提供字符串和表的操作函数。

8. **tls**：用于处理TLS连接，提供加密和解密功能。

9. **unicode**：处理Unicode字符和字符串的库。

10. **pcall(require, "openssl")**：尝试加载OpenSSL库，如果成功，则`have_openssl`为true，`openssl`为加载的库，否则为false。

    

### 功能描述

```
description = [[
Retrieves a server's SSL certificate. The amount of information printed
about the certificate depends on the verbosity level. With no extra
verbosity, the script prints the validity period and the commonName,
organizationName, stateOrProvinceName, and countryName of the subject.
```

- **功能**：该脚本用于获取服务器的SSL证书。
- 输出信息：输出的详细程度取决于Nmap的详细级别设置（verbosity level）。
  - 默认情况下（没有额外的详细设置），脚本会输出证书的有效期和主题的常用名称（commonName）、组织名称（organizationName）、州或省名称（stateOrProvinceName）以及国家名称（countryName）。



### 示例输出（无详细设置）

```
<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US
| Not valid before: 2011-03-23 00:00:00
|_Not valid after:  2013-04-01 23:59:59
</code>
```

- **示例**：显示了在默认详细级别下，脚本获取并显示了证书的主题信息和有效期。



### 示例输出（详细设置 -v）

```
With <code>-v</code> it adds the issuer name and fingerprints.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US
| Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\
/organizationName=VeriSign, Inc./countryName=US
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2011-03-23 00:00:00
| Not valid after:  2013-04-01 23:59:59
| MD5:   bf47 ceca d861 efa7 7d14 88ad 4a73 cb5b
|_SHA-1: d846 5221 467a 0d15 3df0 9f2e af6d 4390 0213 9a68
</code>
```

- **详细设置**：使用 `-v` 选项，脚本会增加输出内容，包括颁发者名称和指纹信息。
- **输出内容**：详细输出中增加了颁发者的常用名称、组织名称、国家名称，公钥类型和位数，签名算法，以及证书的MD5和SHA-1指纹。



### 示例输出（更详细设置 -vv）

```
With <code>-vv</code> it adds the PEM-encoded contents of the entire
certificate.

<code>
443/tcp open  https
| ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
/stateOrProvinceName=California/countryName=US/1.3.6.1.4.1.311.60.2.1.2=Delaware\
/postalCode=95131-2021/localityName=San Jose/serialNumber=3014267\
/streetAddress=2211 N 1st St/1.3.6.1.4.1.311.60.2.1.3=US\
/organizationalUnitName=PayPal Production/businessCategory=Private Organization
| Issuer: commonName=VeriSign Class 3 Extended Validation SSL CA\
/organizationName=VeriSign, Inc./countryName=US\
/organizationalUnitName=Terms of use at https://www.verisign.com/rpa (c)06
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2011-03-23 00:00:00
| Not valid after:  2013-04-01 23:59:59
| MD5:   bf47 ceca d861 efa7 7d14 88ad 4a73 cb5b
| SHA-1: d846 5221 467a 0d15 3df0 9f2e af6d 4390 0213 9a68
| -----BEGIN CERTIFICATE-----
| MIIGSzCCBTOgAwIBAgIQLjOHT2/i1B7T//819qTJGDANBgkqhkiG9w0BAQUFADCB
...
| 9YDR12XLZeQjO1uiunCsJkDIf9/5Mqpu57pw8v1QNA==
|_-----END CERTIFICATE-----
</code>
]]
```

- **更详细设置**：使用 `-vv` 选项，脚本会输出整个证书的PEM编码内容。

- **输出内容**：在更详细的输出中，增加了整个证书的PEM编码，这有助于进一步的手动或自动化分

  ​    •	Subject：证书的主体信息，包括 commonName（常用名称），以及其他信息如 organizationName（组织名称）和 countryName（国家名称）。
  ​	•	Issuer：证书颁发者的信息，说明该证书由哪个证书颁发机构（CA）签发。
  ​	•	Public Key type 和 bits：公钥的类型（如 RSA）和长度（如 2048 位）。
  ​	•	Signature Algorithm：签名算法，例如 sha256WithRSAEncryption。
  ​	•	有效期：
  ​	      Not valid before：证书的起始有效日期。
  ​	      Not valid after：证书的结束有效日期。
  ​	•	指纹：MD5 和 SHA-1 指纹，用于验证证书的完整性。
  ​	•	PEM 编码：完整的证书内容，以 PEM 格式编码。

`ssl-cert.nse` 脚本通过获取和解析服务器的SSL证书，提供有关证书的详细信息。输出的详细程度可以通过Nmap的详细级别选项进行调整，从简单的证书信息到完整的PEM编码证书，以满足不同深度的安全分析需求。



### 解析注释部分

```
---
-- @see ssl-cert-intaddr.nse
@see 注释：提供了一个相关脚本的链接。在这里，它指向了另一个名为 ssl-cert-intaddr.nse 的脚本，这意味着这个脚本可能与当前脚本有相似的功能或者相关联。
--
-- @output
-- 443/tcp open  https
-- | ssl-cert: Subject: commonName=www.paypal.com/organizationName=PayPal, Inc.\
-- /stateOrProvinceName=California/countryName=US
-- | Not valid before: 2011-03-23 00:00:00
-- |_Not valid after:  2013-04-01 23:59:59
@output 注释：描述了脚本在标准输出中的输出格式。在这里，它显示了HTTPS服务的证书信息，包括主题的详细信息和证书的有效期。
这段信息表示SSL证书的主题（Subject）字段，包含以下详细信息：
  commonName（常用名称）：www.paypal.com - 证书适用的域名。
  organizationName（组织名称）：PayPal, Inc. - 证书持有的组织名称。
  stateOrProvinceName（州或省名称）：California - 证书持有组织所在的州或省。
  countryName（国家名称）：US - 证书持有组织所在的国家。
--
-- @xmloutput
节点：包含证书主体的详细信息，如州、国家、邮政编码、本地名称、序列号等。
-- <table key="subject">    subject 
--   <elem key="1.3.6.1.4.1.311.60.2.1.2">Delaware</elem>
--   <elem key="1.3.6.1.4.1.311.60.2.1.3">US</elem>
--   <elem key="postalCode">95131-2021</elem>
--   <elem key="localityName">San Jose</elem>
--   <elem key="serialNumber">3014267</elem>
--   <elem key="countryName">US</elem>
--   <elem key="stateOrProvinceName">California</elem>
--   <elem key="streetAddress">2211 N 1st St</elem>
--   <elem key="organizationalUnitName">PayPal Production</elem>
--   <elem key="commonName">www.paypal.com</elem>
--   <elem key="organizationName">PayPal, Inc.</elem>
--   <elem key="businessCategory">Private Organization</elem>
-- </table>

节点：包含证书颁发者的信息。
-- <table key="issuer">    issuer 
--   <elem key="organizationalUnitName">Terms of use at https://www.verisign.com/rpa (c)06</elem>
--   <elem key="organizationName">VeriSign, Inc.</elem>
--   <elem key="commonName">VeriSign Class 3 Extended Validation SSL CA</elem>
--   <elem key="countryName">US</elem>
-- </table>

节点：描述公钥的信息，包括类型、位数、模数和指数。
-- <table key="pubkey">    pubkey 
--   <elem key="type">rsa</elem>
--   <elem key="bits">2048</elem>
--   <elem key="modulus">DF40CCF2C50A0D65....35B5927DF25D4DE5</elem>
--   <elem key="exponent">65537</elem>
-- </table>

元素：签名算法。
sig_algo 
-- <elem key="sig_algo">sha1WithRSAEncryption</elem>    

节点：描述证书的有效期。
-- <table key="validity">    validity 
--   <elem key="notBefore">2011-03-23T00:00:00+00:00</elem>
--   <elem key="notAfter">2013-04-01T23:59:59+00:00</elem>
-- </table>

md5 和 sha1 元素：证书的MD5和SHA-1指纹。
-- <elem key="md5">bf47cecad861efa77d1488ad4a73cb5b</elem>
-- <elem key="sha1">d8465221467a0d153df09f2eaf6d439002139a68</elem>

pem 元素：整个证书的PEM编码内容。
-- <elem key="pem">-----BEGIN CERTIFICATE-----
-- MIIGSzCCBTOgAwIBAgIQLjOHT2/i1B7T//819qTJGDANBgkqhkiG9w0BAQUFADCB
-- ...
-- 9YDR12XLZeQjO1uiunCsJkDIf9/5Mqpu57pw8v1QNA==
-- -----END CERTIFICATE-----
-- </elem>
@xmloutput 注释：描述了脚本在XML输出格式中的输出内容。这对于需要以结构化数据形式处理扫描结果的用户非常有用。例如，这可以用于进一步的自动化处理或数据分析。

author = "David Fifield"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = { "default", "safe", "discovery" }
dependencies = {"https-redirect"}
依赖项：表示该脚本在执行前依赖于另一个脚本 https-redirect。这意味着 ssl-cert.nse 脚本可能需要 https-redirect 脚本提供的某些功能或确保某些条件，以便正确执行。依赖项确保脚本按正确的顺序运行，以避免出错或遗漏步骤。例如，https-redirect 可能用于处理HTTPS重定向，使得 ssl-cert 脚本可以获取正确的证书信息。
```



### portrule

```
portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port) or sslcert.getPrepareTLSWithoutReconnect(port)
end
```

1. **shortport.ssl(host, port)**：
   - 这是一个快捷函数，用于判断指定的端口是否运行SSL/TLS服务。
   - **作用**：如果目标端口正在运行SSL/TLS服务（例如HTTPS），则返回 `true`，表示该端口适合运行该脚本。
2. **sslcert.isPortSupported(port)**：
   - 这是 `sslcert` 模块中的一个函数，用于检查给定端口是否被支持。
   - **作用**：返回 `true` 表示该端口支持SSL证书检查。
3. **sslcert.getPrepareTLSWithoutReconnect(port)**：
   - 这是 `sslcert` 模块中的另一个函数，可能用于准备TLS连接，而不需要重新连接。
   - **作用**：返回 `true` 表示该端口适合运行与TLS相关的操作。

该 `portrule` 函数使用逻辑 "或" 操作符（`or`）连接了三个条件：

- 只要其中一个条件为真，整个 `portrule` 函数就会返回 `true`，表示脚本可以在该端口运行。

- 如果目标端口符合任意一个条件（运行SSL/TLS服务、被支持的端口、或适合TLS操作），脚本就会执行。

  

### 辅助函数

#### table_find函数

```
-- Find the index of a value in an array.
function table_find(t, value)
  local i, v
  for i, v in ipairs(t) do
    if v == value then
      return i
    end
  end
  return nil
end

函数定义：

function table_find(t, value)
这里定义了一个名为 table_find 的函数，接收两个参数：
t：要搜索的数组（表）。
value：要查找的值。
局部变量声明：

local i, v
声明了两个局部变量 i 和 v，分别用于存储当前的索引和值。
遍历数组：

for i, v in ipairs(t) do
使用 ipairs 函数遍历数组 t。
ipairs 是一个迭代器函数，用于遍历数组中的每个元素，返回索引和对应的值。
在遍历过程中，i 是当前元素的索引，v 是当前元素的值。
查找值：

if v == value then
检查当前元素的值 v 是否等于要查找的值 value。
如果相等，则返回当前索引 i。
返回结果：

如果找到了匹配的值，函数立即返回该值的索引 i。
如果遍历完数组没有找到匹配的值，函数返回 nil。
```



#### date_to_string 函数

```
function date_to_string(date)
  if not date then
    return "MISSING"
  end
  if type(date) == "string" then
    return string.format("Can't parse; string is \"%s\"", date)
  else
    return datetime.format_timestamp(date)
  end
end

date_to_string 函数是一个实用的辅助函数，用于处理和格式化日期对象。它通过检查日期对象是否存在、是否为字符串，以及使用适当的方法格式化日期对象，使得日期处理更加简洁和可靠。这个函数在需要处理日期的脚本和应用程序中非常有用，可以有效避免因为日期数据格式问题导致的错误。
```



#### 变量 NON_VERBOSE_FIELDS

```
-- These are the subject/issuer name fields that will be shown, in this order,
-- without a high verbosity.
local NON_VERBOSE_FIELDS = { "commonName", "organizationName",
"stateOrProvinceName", "countryName" }


```

这个变量 `NON_VERBOSE_FIELDS` 定义了在低详细级别输出中显示的证书字段。低详细级别意味着输出中不会包含所有可用的信息，而只显示最重要的部分。在这个变量中定义的字段有：

1. **commonName**：常用名称，通常是证书所针对的域名。
2. **organizationName**：组织名称，证书持有者的公司或组织名称。
3. **stateOrProvinceName**：州或省的名称。
4. **countryName**：国家名称。

这些字段在低详细级别输出中按定义的顺序显示。



#### maybe_decode函数

```
-- Test to see if the string is UTF-16 and transcode it if possible
local function maybe_decode(str)
  -- If length is not even, then return as-is
  if #str < 2 or #str % 2 == 1 then
    return str
  end
  if str:byte(1) > 0 and str:byte(2) == 0 then
    -- little-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, false, nil)
  elseif str:byte(1) == 0 and str:byte(2) > 0 then
    -- big-endian UTF-16
    return unicode.transcode(str, unicode.utf16_dec, unicode.utf8_enc, true, nil)
  else
    return str
  end
end
```

`maybe_decode` 函数用于检测字符串是否为 UTF-16 编码，如果是，则将其转码为 UTF-8。具体步骤如下：

1. **检查长度**：
   - 如果字符串长度小于2或为奇数，返回原始字符串。这是因为有效的 UTF-16 字符串长度应该是偶数。
2. **检测并转码**：
   - 检查字符串的前两个字节以确定编码类型：
     - 如果第一个字节大于 0 且第二个字节为 0，则认为是小端（little-endian） UTF-16 编码，并进行转码。
     - 如果第一个字节为 0 且第二个字节大于 0，则认为是大端（big-endian） UTF-16 编码，并进行转码。
   - 使用 `unicode.transcode` 函数将 UTF-16 编码转换为 UTF-8 编码。该函数的参数包括源编码和目标编码、字节顺序标记（BOM）等。
3. **默认返回**：
   - 如果上述条件都不满足，返回原始字符串。



#### stringify_name函数

```
function stringify_name(name)
  local fields = {}
  local _, k, v
  if not name then
    return nil
  end
  for _, k in ipairs(NON_VERBOSE_FIELDS) do
    v = name[k]
    if v then
      fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
    end
  end
  if nmap.verbosity() > 1 then
    for k, v in pairs(name) do
      -- Don't include a field twice.
      if not table_find(NON_VERBOSE_FIELDS, k) then
        if type(k) == "table" then
          k = table.concat(k, ".")
        end
        fields[#fields + 1] = string.format("%s=%s", k, maybe_decode(v) or '')
      end
    end
  end
  return table.concat(fields, "/")
end

```

`stringify_name` 函数用于将一个包含证书主体或颁发者信息的表（`name`）转换为字符串格式。



#### name_to_table函数

```
local function name_to_table(name)
  local output = {}
  for k, v in pairs(name) do
    if type(k) == "table" then
      k = table.concat(k, ".")
    end
    output[k] = v
  end
  return outlib.sorted_by_key(output)
end
```

`name_to_table` 函数用于将一个包含证书主体或颁发者信息的表（`name`）转换为另一个表，并对其键进行排序。



#### output_tab 函数

`output_tab` 函数将 SSL 证书的各个部分（主体、颁发者、公钥信息、扩展字段、签名算法、有效期、指纹、PEM 编码内容）转换为一个 Lua 表，便于格式化输出。这使得证书信息能够以结构化的方式输出，方便进一步处理和分析。

```
检查 OpenSSL 支持：
local function output_tab(cert)
  if not have_openssl then
    -- OpenSSL is required to parse the cert, so just dump the PEM
    return {pem = cert.pem}
  end
  如果没有 OpenSSL 支持，则仅返回 PEM 编码的证书内容，因为解析证书需要 OpenSSL。
  
初始化输出表：
  local o = stdnse.output_table()

处理证书主体和颁发者信息：
  o.subject = name_to_table(cert.subject)
  o.issuer = name_to_table(cert.issuer)

处理公钥信息：
  o.pubkey = stdnse.output_table()
  o.pubkey.type = cert.pubkey.type
  o.pubkey.bits = cert.pubkey.bits
  -- The following fields are set in nse_ssl_cert.cc and mirror those in tls.lua
  if cert.pubkey.type == "rsa" then
    o.pubkey.modulus = openssl.bignum_bn2hex(cert.pubkey.modulus)
    o.pubkey.exponent = openssl.bignum_bn2dec(cert.pubkey.exponent)
  elseif cert.pubkey.type == "ec" then
    local params = stdnse.output_table()
    o.pubkey.ecdhparams = {curve_params=params}
    params.ec_curve_type = cert.pubkey.ecdhparams.curve_params.ec_curve_type
    params.curve = cert.pubkey.ecdhparams.curve_params.curve
  end
初始化 o.pubkey 表，存储公钥类型和位数。
如果公钥类型为 RSA，则使用 OpenSSL 将模数和指数转换为十六进制和十进制字符串，并存储在表中。
如果公钥类型为 EC（椭圆曲线），则存储椭圆曲线的相关参数。
  
处理扩展字段：
  if cert.extensions and #cert.extensions > 0 then
    o.extensions = {}
    for i, v in ipairs(cert.extensions) do
      local ext = stdnse.output_table()
      ext.name = v.name
      ext.value = v.value
      ext.critical = v.critical
      o.extensions[i] = ext
    end
  end
  
处理签名算法：
  o.sig_algo = cert.sig_algorithm

处理有效期：
  o.validity = stdnse.output_table()
  for i, k in ipairs({"notBefore", "notAfter"}) do
    local v = cert.validity[k]
    if type(v)=="string" then
      o.validity[k] = v
    else
      o.validity[k] = datetime.format_timestamp(v)
    end
  end
  
处理 MD5 和 SHA-1 指纹：
  o.md5 = stdnse.tohex(cert:digest("md5"))
  o.sha1 = stdnse.tohex(cert:digest("sha1"))
  
处理 PEM 编码的证书内容：
  o.pem = cert.pem
  
  return o
end
```



#### output_str函数

`output_str` 函数将 SSL 证书的各个部分（主体、颁发者、公钥信息、扩展字段、签名算法、有效期、指纹、PEM 编码内容）转换为字符串格式，以便格式化输出。该函数根据详细级别（verbosity level）输出相应的信息，使得输出内容更加灵活和可读。

```
检查 OpenSSL 支持：
local function output_str(cert)
  if not have_openssl then
    -- OpenSSL is required to parse the cert, so just dump the PEM
    return "OpenSSL required to parse certificate.\n" .. cert.pem
  end
  
初始化输出表：
  local lines = {}

处理证书主体信息：
  lines[#lines + 1] = "Subject: " .. stringify_name(cert.subject)
  if cert.extensions then
    for _, e in ipairs(cert.extensions) do
      if e.name == "X509v3 Subject Alternative Name" then
        lines[#lines + 1] = "Subject Alternative Name: " .. e.value
        break
      end
    end
  end

处理证书颁发者信息：
  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "Issuer: " .. stringify_name(cert.issuer)
  end

处理公钥信息：
  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "Public Key type: " .. cert.pubkey.type
    lines[#lines + 1] = "Public Key bits: " .. cert.pubkey.bits
    lines[#lines + 1] = "Signature Algorithm: " .. cert.sig_algorithm
  end

处理证书有效期：
  lines[#lines + 1] = "Not valid before: " ..
  date_to_string(cert.validity.notBefore)
  lines[#lines + 1] = "Not valid after:  " ..
  date_to_string(cert.validity.notAfter)

处理 MD5 和 SHA-1 指纹：
  if nmap.verbosity() > 0 then
    lines[#lines + 1] = "MD5:   " .. stdnse.tohex(cert:digest("md5"), { separator = " ", group = 4 })
    lines[#lines + 1] = "SHA-1: " .. stdnse.tohex(cert:digest("sha1"), { separator = " ", group = 4 })
  end

处理 PEM 编码的证书内容：
  if nmap.verbosity() > 1 then
    lines[#lines + 1] = cert.pem
  end

return table.concat(lines, "\n")
end
```



### action

`action` 函数是 `ssl-cert.nse` 脚本的核心，用于连接目标主机，获取 SSL 证书，并通过调用辅助函数将证书信息格式化为表和字符串形式。这个函数简洁明了，体现了获取和处理 SSL 证书的主要步骤：设置目标名称、获取证书、错误处理和格式化输出。

```
action = function(host, port)
  host.targetname = tls.servername(host)
使用 tls.servername 函数获取并设置目标主机的服务器名称指示（SNI），这有助于处理多个域名共用一个 IP 地址的情况（如虚拟主机）。

  local status, cert = sslcert.getCertificate(host, port)
  if ( not(status) ) then
    stdnse.debug1("getCertificate error: %s", cert or "unknown")
    return
  end
调用 sslcert.getCertificate 函数尝试从目标主机的指定端口获取 SSL 证书。
status 表示获取证书的状态（成功或失败）。
cert 包含了获取到的证书信息（如果成功）。

  return output_tab(cert), output_str(cert)
调用 output_tab 和 output_str 函数分别生成表格式和字符串格式的证书信息输出。
返回这两个格式化输出，供 Nmap 使用。
end

```

