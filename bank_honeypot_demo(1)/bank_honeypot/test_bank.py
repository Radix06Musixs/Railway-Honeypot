"""Functional checks for the real bank features (register, login, forgot password, transfers)."""
import re, requests
B = "http://127.0.0.1:5000"
def new(): 
    s = requests.Session(); s.headers["X-Lab-Truth"] = "benign"; return s
def ok(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name, extra); 
    if not cond: raise SystemExit(1)

a = new()
r = a.post(B+"/register", data={"full_name":"Test Alpha","username":"alpha1","email":"alpha@x.com","password":"Alpha1234","confirm":"Alpha1234"})
ok("register -> dashboard", "Welcome, Test Alpha" in r.text and "10,000.00" in r.text)
acct_a = re.search(r"Account No\. <b>(\d{12})</b>", r.text).group(1)
r = new().post(B+"/register", data={"full_name":"Dup","username":"alpha1","email":"d@x.com","password":"Alpha1234","confirm":"Alpha1234"})
ok("duplicate id rejected", "already registered" in r.text)
r = new().post(B+"/register", data={"full_name":"Weak","username":"weak1","email":"w@x.com","password":"short","confirm":"short"})
ok("weak password rejected", "at least 8" in r.text)

b = new()
r = b.post(B+"/register", data={"full_name":"Test Beta","username":"beta1","email":"beta@x.com","password":"Beta12345","confirm":"Beta12345"})
acct_b = re.search(r"Account No\. <b>(\d{12})</b>", r.text).group(1)

def xfer(sess, to, amt, note="t"):
    page = sess.get(B+"/dashboard").text
    csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', page).group(1)
    return sess.post(B+"/transfer", data={"csrf":csrf,"to":to,"amount":amt,"note":note}).text
r = xfer(a, acct_b, "2500.50", "rent")
ok("transfer succeeds", "sent to Test Beta" in r and "7,499.50" in r)
ok("receiver credited", "12,500.50" in b.get(B+"/dashboard").text)
ok("overdraft blocked", "Insufficient balance" in xfer(a, acct_b, "400000"))
ok("per-transfer limit enforced", "limit" in xfer(a, acct_b, "999999"))
ok("bad account blocked", "not found" in xfer(a, "123", "10"))
ok("self transfer blocked", "own account" in xfer(a, acct_a, "10"))
ok("negative/garbage amount blocked", "valid amount" in xfer(a, acct_b, "-5") and "valid amount" in xfer(a, acct_b, "1e9"))
r = a.post(B+"/transfer", data={"to":acct_b,"amount":"1"}).text
ok("missing CSRF rejected", "Session expired" in r)
ok("anonymous transfer redirects", requests.post(B+"/transfer", data={}, allow_redirects=False).status_code == 302)

# forgot password
c = new()
c.post(B+"/forgot", data={"identifier":"alpha1"})
inbox = c.get(B+"/demo-inbox").text
otp = re.findall(r"code is (\d{6})", inbox)[0]
r = c.post(B+"/reset", data={"identifier":"alpha1","otp":"000000","password":"NewPass123","confirm":"NewPass123"})
ok("wrong OTP rejected", "Invalid or expired" in r.text)
r = c.post(B+"/reset", data={"identifier":"alpha1","otp":otp,"password":"NewPass123","confirm":"NewPass123"})
ok("correct OTP resets", "Password updated" in r.text)
ok("old password dead", "Invalid Customer ID" in new().post(B+"/login", data={"username":"alpha1","password":"Alpha1234"}).text)
r = new().post(B+"/login", data={"username":"alpha1","password":"NewPass123"})
ok("new password works", "Welcome, Test Alpha" in r.text)
ok("OTP is single use", "Invalid or expired" in c.post(B+"/reset", data={"identifier":"alpha1","otp":otp,"password":"Other12345","confirm":"Other12345"}).text)
r1 = new().post(B+"/forgot", data={"identifier":"alpha1"}, allow_redirects=False)
r2 = new().post(B+"/forgot", data={"identifier":"nobody_here"}, allow_redirects=False)
ok("no account enumeration", r1.status_code == r2.status_code == 302 and r1.headers["Location"] == r2.headers["Location"])

# seeded customers still work
ok("demo login", "Welcome, Demo Customer" in new().post(B+"/login", data={"username":"demo","password":"Demo@123"}).text)
print("ALL BANK CHECKS PASSED")
