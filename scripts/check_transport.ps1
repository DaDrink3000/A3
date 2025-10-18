param([string]$Domain = "localhost")

# 1) HTTP should 301 to HTTPS
$code = (curl.exe -s -o $null -w "%{http_code}" "http://$Domain/") 2>$null
$loc  = (curl.exe -s -I "http://$Domain/" | Select-String -Pattern '^location:' -CaseSensitive).ToString()
if ($code -ne 301) { throw "FAIL: no 301 redirect" }
if ($loc -notmatch 'https://') { throw "FAIL: redirect not https" }
"OK: HTTP->HTTPS 301"

# 2) HSTS present
if (!(curl.exe -k -s -I "https://$Domain/" | Select-String -Pattern '^strict-transport-security:' -CaseSensitive)) {
  throw "FAIL: HSTS missing"
}
"OK: HSTS present"

# 3) Cookie flags on login
if (curl.exe -k -s -I "https://$Domain/login" | Select-String -Pattern 'Set-Cookie:.*Secure;.*HttpOnly' -CaseSensitive) {
  "OK: Cookie Secure+HttpOnly"
} else {
  "WARN: Cookie flags not detected"
}
