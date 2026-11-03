// Real browser smoke test. Build the CLI and install Playwright/Chromium first.
const assert = require('node:assert/strict');
const {spawn,spawnSync} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {chromium} = require('playwright');
const binary=path.resolve(process.env.SECURE_INPUT_BINARY || './secure-input');
const port=process.env.SECURE_INPUT_TEST_PORT || '18987';
const base='http://127.0.0.1:'+port;
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'secure-input-ui-'));
const server=spawn(binary,['serve','--addr','127.0.0.1:'+port],{stdio:'ignore'});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
function request(name,extra=[]){
 const out=path.join(dir,name+'.env');
 const result=spawnSync(binary,['request','--server',base,'--out',out,'--reason','Browser acceptance test','--var','TOKEN','--var','REGION','--public','REGION','--no-wait',...extra],{encoding:'utf8'});
 assert.equal(result.status,0,result.stderr);
 const lines=result.stdout.trim().split('\n');
 return {out,url:lines[0],id:lines[1].replace('request id: ','')};
}
(async()=>{
 for(let i=0;i<50;i++){try{if((await fetch(base)).ok)break;}catch{}await sleep(100);}
 const browser=await chromium.launch({headless:true});
 try{
 const page=await browser.newPage();
 const errors=[];page.on('pageerror',e=>errors.push(String(e)));
 // Actual page encrypts; relay returns opaque payload; CLI decrypts and masks.
 const first=request('encrypted');
 await page.goto(first.url);
 await page.locator('#v0').fill('browser-secret-测试-🔐');
 await page.locator('#v1').fill('us-west');
 let body;
 page.on('request',r=>{if(r.url().endsWith('/submit'))body=r.postData();});
 await page.locator('#submit').click();
 await page.getByText('The agent has been notified. You can close this tab.').waitFor();
 assert(body&&!body.includes('browser-secret'));assert(!JSON.parse(body).entries);assert(JSON.parse(body).encrypted);
 const pull=spawnSync(binary,['pull','--server',base,'--id',first.id,'--out',first.out],{encoding:'utf8'});
 assert.equal(pull.status,0,pull.stderr);assert(!pull.stdout.includes('browser-secret'));assert(pull.stdout.includes('TOKEN=********'));assert(pull.stdout.includes('REGION=us-west'));
 assert(fs.readFileSync(first.out,'utf8').includes('browser-secret-测试-🔐'));
 assert(!fs.existsSync(first.out+'.secure-input-key.json'));
 assert.equal((await fetch(base+'/api/requests/'+first.id+'/result')).status,410);
 // Mismatched pin locks the form before secrets can be entered.
 const mismatch=request('mismatch');
 await page.goto(mismatch.url.split('#')[0]+'#e2ee=wrong');
 await page.locator('#error:not([hidden])').waitFor();
 assert(await page.locator('#submit').isDisabled());assert(await page.locator('#v0').isDisabled());
 // Crypto unavailable: no network submission and no plaintext fallback.
 const unavailable=request('unavailable');
 const insecurePage=await browser.newPage();
 await insecurePage.addInitScript(()=>Object.defineProperty(globalThis,'isSecureContext',{value:false}));
 await insecurePage.goto(unavailable.url);
 await insecurePage.locator('#error:not([hidden])').waitFor();assert(await insecurePage.locator('#submit').isDisabled());
 await insecurePage.close();
 // A failed encrypted submit retains values and allows a fresh encryption retry.
 const retry=request('retry');await page.goto(retry.url);await page.locator('#v0').fill('retry-secret');
 let failed=false;let attempts=[];
 await page.route('**/submit',async route=>{attempts.push(JSON.parse(route.request().postData()));if(!failed){failed=true;await route.fulfill({status:503,body:'temporary'});}else await route.continue();});
 await page.locator('#submit').click();await page.locator('#error:not([hidden])').waitFor();assert.equal(await page.locator('#v0').inputValue(),'retry-secret');
 await page.locator('#submit').click();await page.getByText('The agent has been notified. You can close this tab.').waitFor();
 assert.equal(attempts.length,2);assert.notEqual(attempts[0].encrypted.ephemeralPublicKey,attempts[1].encrypted.ephemeralPublicKey);assert.notEqual(attempts[0].encrypted.nonce,attempts[1].encrypted.nonce);
 await page.unroute('**/submit');
 // Submit/decline cannot race while encryption/upload is in flight.
 const race=request('race');await page.goto(race.url);await page.locator('#v0').fill('race-secret');
 let release;let seen;const captured=new Promise(r=>seen=r);
 await page.route('**/submit',async route=>{seen();await new Promise(r=>release=r);await route.continue();});
 await page.locator('#submit').click();await captured;assert(await page.locator('#decline').isDisabled());assert(await page.locator('#submit').isDisabled());release();await page.getByText('The agent has been notified. You can close this tab.').waitFor();await page.unroute('**/submit');
 // Decline failures must not claim that no values were sent.
 const decline=request('decline');await page.goto(decline.url);await page.locator('#v0').fill('not-submitted');
 page.on('dialog',dialog=>dialog.accept());
 await page.route('**/decline',route=>route.fulfill({status:410,body:'gone'}));await page.locator('#decline').click();await page.locator('#error:not([hidden])').waitFor();assert((await page.locator('#error').textContent()).includes('Could not decline'));assert.equal(await page.locator('#v0').inputValue(),'not-submitted');await page.unroute('**/decline');
 await page.locator('#decline').click();await page.getByText('Request declined. You can close this tab.').waitFor();
 const declinedPull=spawnSync(binary,['pull','--server',base,'--id',decline.id,'--out',decline.out],{encoding:'utf8'});assert.equal(declinedPull.status,2);assert(!fs.existsSync(decline.out+'.secure-input-key.json'));
 // Explicit plaintext still works and is visibly labelled.
 const legacy=request('legacy',['--no-encryption']);await page.goto(legacy.url);await page.getByText('Encryption is disabled for this request.',{exact:false}).waitFor();await page.locator('#v0').fill('legacy-secret');await page.locator('#submit').click();await page.getByText('The agent has been notified. You can close this tab.').waitFor();assert(JSON.parse(body).entries);assert(body.includes('legacy-secret'));
 const legacyPull=spawnSync(binary,['pull','--server',base,'--id',legacy.id,'--out',legacy.out,'--no-encryption'],{encoding:'utf8'});assert.equal(legacyPull.status,0,legacyPull.stderr);
 assert.deepEqual(errors,[]);console.log('PASS: Chromium encrypted round trip, masking, single use, key pin, missing crypto, retry freshness, submit/decline mutex, decline errors, legacy opt-out.');
 }finally{await browser.close();}
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>{server.kill();fs.rmSync(dir,{recursive:true,force:true});});
