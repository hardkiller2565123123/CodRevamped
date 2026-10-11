#pragma once

inline constexpr const char *publicDashboard =
    R"DASH1(<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Replay DW · Server status</title>
<style>
:root{color-scheme:dark;--bg:#0b111b;--panel:#131d2a;--line:#253247;--muted:#98a9bd;--ink:#edf4fc;--green:#64e4b3;--blue:#72b8ff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 90% 0,#182c43,transparent 50%),var(--bg);color:var(--ink);font:15px system-ui,sans-serif}main{max-width:1240px;margin:auto;padding:44px 28px}header{display:flex;align-items:center;justify-content:space-between;gap:24px;margin-bottom:32px}.eyebrow{font-size:11px;letter-spacing:2px;color:var(--blue);font-weight:700}h1{font-size:34px;letter-spacing:-1px;margin:9px 0}p{color:var(--muted);line-height:1.6;margin:6px 0}.badge{border:1px solid #315449;border-radius:30px;padding:10px 16px;color:var(--green);white-space:nowrap}.badge.stale{color:#ffd494;border-color:#765d36}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}.card{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:22px}.label{color:var(--muted);font-size:13px}.value{font-size:34px;font-weight:650;letter-spacing:-1px;margin:12px 0 8px;font-variant-numeric:tabular-nums}.note{font-size:12px;color:var(--muted)}.sections{display:grid;grid-template-columns:1.25fr 1fr;gap:16px;margin-top:16px}h2{font-size:17px;margin:0 0 20px}canvas{width:100%;height:170px;display:block}.chart-head{display:flex;justify-content:space-between;gap:12px}.rows{display:grid;grid-template-columns:1fr 1fr;gap:0 24px}.row{display:flex;justify-content:space-between;gap:12px;padding:13px 0;border-top:1px solid var(--line);font-size:13px}.row span{color:var(--muted)}.row strong{font-weight:550;text-align:right;font-variant-numeric:tabular-nums}.bar{height:5px;border-radius:5px;background:var(--line);margin:15px 0 9px;overflow:hidden}.bar i{display:block;height:100%;background:var(--blue);width:0}footer{display:flex;justify-content:space-between;gap:16px;color:var(--muted);font-size:12px;margin-top:25px}.full{grid-column:1/-1}@media(max-width:850px){.grid{grid-template-columns:repeat(2,1fr)}.sections{grid-template-columns:1fr}}@media(max-width:480px){main{padding:24px 16px}header{align-items:flex-start;flex-direction:column}h1{font-size:29px}.card{padding:18px}.value{font-size:27px}.rows{grid-template-columns:1fr}footer{flex-direction:column}}

.activity-layout{display:grid;grid-template-columns:1.35fr 1fr;gap:16px;margin:16px 0}.activity-card{margin-top:16px}.section-head{display:flex;justify-content:space-between;align-items:baseline;gap:14px}.section-head h2{margin-bottom:10px}.count{color:var(--blue);font-size:12px}.empty{padding:22px 0;color:var(--muted);font-size:13px}.player-table{width:100%;border-collapse:collapse;text-align:left;font-size:13px}.player-table th{color:var(--muted);font-size:11px;font-weight:500;padding:12px 8px;border-bottom:1px solid var(--line)}.player-table td{padding:13px 8px;border-bottom:1px solid var(--line);vertical-align:top}.player-table th:first-child,.player-table td:first-child{padding-left:0}.pill{display:inline-block;border:1px solid var(--line);background:#18283a;color:var(--blue);border-radius:7px;font-size:11px;padding:4px 7px}.pill.live{color:var(--green);border-color:#315449}.party-box,.match-box{border:1px solid var(--line);border-radius:12px;padding:17px;margin-top:12px;background:#101925}.party-title,.match-title{display:flex;justify-content:space-between;gap:12px;align-items:center}.party-title strong,.match-title strong{font-size:15px}.members{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px}.member{background:#1d2b3e;border-radius:7px;padding:6px 9px;font-size:12px}.match-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.match-meta{font-size:12px;color:var(--muted);margin:12px 0;line-height:1.7;overflow-wrap:anywhere}.team-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.team{border-left:2px solid var(--blue);padding:5px 0 5px 12px}.team-label{color:var(--muted);font-size:11px;margin-bottom:8px}.team-player{display:flex;justify-content:space-between;gap:6px;align-items:center;font-size:12px;margin:8px 0;overflow-wrap:anywhere}.table-wrap{overflow-x:auto}.notice{font-size:12px;color:var(--muted);line-height:1.6}.player-name{overflow-wrap:anywhere}.link-label{color:var(--blue)}@media(max-width:850px){.activity-layout,.match-grid{grid-template-columns:1fr}}@media(max-width:480px){.team-grid{grid-template-columns:1fr}.player-table th,.player-table td{padding:11px 5px}}
</style></head><body><main>
<header><div><div class="eyebrow">IW8 REPLAY / DEMONWARE</div><h1>Server overview</h1><p>Public telemetry · Match controls require an operator key.</p></div><div class="badge" id="health" role="status">Connecting…</div></header>
<div class="grid">
<div class="card"><div class="label">Online players</div><div class="value" id="players">—</div><div class="note">Unique players with a valid lobby session</div></div>
<div class="card"><div class="label">Server uptime</div><div class="value" id="uptime">—</div><div class="note">Time since this backend started</div></div>
<div class="card"><div class="label">Native tasks</div><div class="value" id="tasks">—</div><div class="note" id="rate">Waiting for a second sample</div></div>
<div class="card"><div class="label">Relay traffic</div><div class="value" id="packets">—</div><div class="note">Forwarded packets since restart</div></div>
</div>
<section class="card activity-card"><div class="section-head"><h2>Matches &amp; lobbies</h2><span class="count" id="match-count">Waiting for live data</span></div><p class="notice">Host-reported state, current authenticated rosters, and published map/mode pools.</p><div class="match-grid" id="match-list"></div></section>
<div class="activity-layout">
<section class="card"><div class="section-head"><h2>Online players</h2><span class="count" id="player-count">—</span></div><div class="table-wrap" id="player-list"></div></section>
<section class="card"><div class="section-head"><h2>Published parties</h2><span class="count" id="party-count">—</span></div><p class="notice">Member groups published to matchmaking. Idle parties that have not published a group are not visible to this backend.</p><div id="party-list"></div></section>
</div>
<div class="sections">
<section class="card"><div class="chart-head"><h2>Task activity</h2><span class="note">Tasks / second · this visit</span></div><canvas id="chart" role="img" aria-label="Recent native task rate"></canvas><p class="note" id="chart-note">History begins when this page opens; samples arrive every 3 seconds.</p></section>
<section class="card"><h2>Connections &amp; authentication</h2><div class="rows"><div class="row"><span>Active TCP connections</span><strong id="connections">—</strong></div><div class="row"><span>TCP connection limit</span><strong id="limit">—</strong></div><div class="row"><span>Platform logins</span><strong id="logins">—</strong></div><div class="row"><span>Native auth successes</span><strong id="auth">—</strong></div><div class="row"><span>Lobby authentications</span><strong id="lobby-auth">—</strong></div><div class="row"><span>Lobby frames</span><strong id="frames">—</strong></div></div><p class="note">TCP includes page requests. Authentication totals count successful events since restart.</p></section>
<section class="card"><h2>Server resources</h2><div class="rows"><div class="row"><span>Backend CPU</span><strong id="cpu">—</strong></div><div class="row"><span>Backend RAM</span><strong id="rss">—</strong></div><div class="row"><span>Host load · 1 minute</span><strong id="load">—</strong></div><div class="row"><span>Available host RAM</span><strong id="memory">—</strong></div></div><div class="bar"><i id="disk-bar"></i></div><div class="row"><span>Disk available / total</span><strong id="disk">—</strong></div><p class="note">CPU uses one core as 100%. Disk covers the runtime filesystem.</p></section>
<section class="card"><h2>Relay &amp; network health</h2><div class="rows"><div class="row"><span>Relay listener</span><strong id="relay">—</strong></div><div class="row"><span>QoS listener</span><strong id="qos">—</strong></div><div class="row"><span>Active relay associations</span><strong id="associations">—</strong></div><div class="row"><span>Verified associations · total</span><strong id="verified">—</strong></div><div class="row"><span>Relay ping replies</span><strong id="pings">—</strong></div><div class="row"><span>Rejected relay packets</span><strong id="rejected">—</strong></div><div class="row"><span>QoS probes</span><strong id="qos-probes">—</strong></div><div class="row"><span>NAT introductions</span><strong id="nat">—</strong></div><div class="row"><span>Lobby failures</span><strong id="failures">—</strong></div><div class="row"><span>Relay error</span><strong id="relay-error">—</strong></div></div></section>
</div><footer><span>Replay 1.20 · Counters reset on server restart · Public player display names · No account IDs or network addresses</span><span id="updated">Auto refresh every 3 seconds</span></footer>
</main><script>
'use strict';
const el=id=>document.getElementById(id),num=v=>Number(v).toLocaleString(),bytes=v=>v==null?'Unavailable':v>=1073741824?(v/1073741824).toFixed(1)+' GiB':(v/1048576).toFixed(1)+' MiB';
let previous=null,history=[];
let operatorKey='';
const startRequests=new Map();
const botCounts=new Map();
async function requestStart(match, button, message, fillBots=false, botCount=0) {
    if (!operatorKey) {
        const value=window.prompt('Enter your operator access key to start this match:');
        if (!value) return;
        operatorKey=value.trim();
    }
    const key=match.start_token+(fillBots ? ':bots' : ':start');
    startRequests.set(key,'Sending request…');
    button.disabled=true; message.textContent='Sending request…';
    try {
        const response=await fetch(fillBots ? '/operator/fill-bots' : '/operator/start-match',{
            method:'POST',headers:{'X-Replay-Operator':operatorKey,'Content-Type':fillBots ? 'application/json' : 'text/plain'},
            body:fillBots ? JSON.stringify({match_token:match.start_token,bot_count:botCount}) : match.start_token,
            signal:AbortSignal.timeout(8000)
        });
        const result=await response.json();
        if (response.status===403) operatorKey='';
        if (!response.ok) throw Error(result.message || 'Start request failed.');
        startRequests.set(key,result.message);
        message.textContent=result.message;
    } catch (error) {
        startRequests.delete(key);
        message.textContent=error.message; button.disabled=false;
    }
}
function chart(){const c=el('chart'),r=c.getBoundingClientRect(),d=window.devicePixelRatio||1;c.width=r.width*d;c.height=r.height*d;const x=c.getContext('2d');x.scale(d,d);const w=r.width,h=r.height,max=Math.max(1,...history);x.strokeStyle='#253247';x.lineWidth=1;for(let i=0;i<4;i++){const y=10+i*(h-30)/3;x.beginPath();x.moveTo(0,y);x.lineTo(w,y);x.stroke()}x.fillStyle='#98a9bd';x.font='11px system-ui';x.fillText(max.toFixed(1)+'/s',0,10);if(history.length<2)return;x.beginPath();history.forEach((v,i)=>{const a=i*w/(history.length-1),b=h-15-v/max*(h-35);i?x.lineTo(a,b):x.moveTo(a,b)});x.strokeStyle='#72b8ff';x.lineWidth=2;x.stroke()}
function element(tag, className, text) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    if (text != null) item.textContent = text;
    return item;
}
function stateLabel(state) {
    return ({in_game:'In game',intermission:'In lobby',countdown:'Starting',forming:'Forming',joining:'Joining',online:'Online',unknown:'State unavailable'})[state] || 'State unavailable';
}
function renderActivity(activity) {
    const players = activity.players, parties = activity.parties, matches = activity.matches;
)DASH1"
    R"DASH2(    el('player-count').textContent = players.length + ' connected';
    el('party-count').textContent = activity.available ? parties.length + ' published' : 'Grouping unavailable';
    el('match-count').textContent = activity.available ? matches.filter(match => match.state === 'in_game').length + ' running · ' + matches.length + ' active lobbies' : 'Grouping unavailable';
    const playerRoot = el('player-list');
    playerRoot.replaceChildren();
    if (!players.length) playerRoot.append(element('div','empty','No players online.'));
    else {
        const table = element('table','player-table'), head = element('thead'), headings = element('tr');
        for (const label of ['Player','Party','Match','Status']) headings.append(element('th',null,label));
        head.append(headings); table.append(head);
        const body = element('tbody');
        for (const player of players) {
            const row = element('tr');
            row.append(element('td','player-name',player.name + (player.host ? ' · Host' : '')),
                element('td','link-label',player.party || 'Not published'),
                element('td','link-label',player.match || '—'), element('td',null,stateLabel(player.state)));
            body.append(row);
        }
        table.append(body); playerRoot.append(table);
    }
    const partyRoot = el('party-list'); partyRoot.replaceChildren();
    if (!parties.length) partyRoot.append(element('div','empty',activity.available ? 'No live party groups published.' : 'Party data unavailable; retrying.'));
    for (const party of parties) {
        const card = element('div','party-box'), title = element('div','party-title');
        title.append(element('strong',null,party.label),element('span','pill',party.match)); card.append(title);
        card.append(element('p','note',party.members.length + ' member' + (party.members.length === 1 ? '' : 's') + ' · Leader: ' + (party.leader || 'Not currently online')));
        const members = element('div','members');
        for (const name of party.members) members.append(element('span','member',name + (name === party.leader ? ' · Leader' : '')));
        card.append(members); partyRoot.append(card);
    }
    const matchRoot = el('match-list'); matchRoot.replaceChildren();
    if (!matches.length) matchRoot.append(element('div','empty',activity.available ? 'No active matches or lobbies.' : 'Match data unavailable; retrying.'));
    for (const match of matches) {
        const card = element('article','match-box'), title = element('div','match-title');
        title.append(element('strong',null,match.label),element('span','pill' + (match.state === 'in_game' ? ' live' : ''),stateLabel(match.state))); card.append(title);
        card.append(element('p','match-meta','Host: ' + match.host + ' · ' + match.members.length + ' / ' + match.capacity + ' online players'));
        card.append(element('p','match-meta','Map pool: ' + (match.maps.join(', ') || 'Not published') + ' · Modes: ' + (match.modes.join(', ') || 'Not published')));
        if (match.can_start) {
            const pending=match.start_requested || startRequests.has(match.start_token+':start');
            const button=element('button','pill',pending ? 'Start requested' : 'Start match');
            button.type='button'; button.disabled=pending;
            button.style.cssText='padding:9px 14px;cursor:pointer;font:inherit';
            const message=element('p','notice',startRequests.get(match.start_token+':start') ||
                (pending ? 'Native start requested.' : 'Start this lobby through the host engine.'));
            message.setAttribute('role','status');
            button.addEventListener('click',()=>requestStart(match,button,message));
            card.append(button,message);
            const botsPending=match.bots_requested || startRequests.has(match.start_token+':bots');
            const available=Math.max(0,match.capacity-match.occupied_slots);
            const count=element('input','pill'); count.type='number'; count.min='1';
            count.max=String(Math.min(199,available)); count.step='1';
            count.value=String(botCounts.get(match.start_token) ?? (match.bot_count || Math.min(11,available)));
            count.setAttribute('aria-label','Number of bots to add');
            count.disabled=botsPending || available===0; count.style.width='80px';
            count.addEventListener('input',()=>botCounts.set(match.start_token,count.value));
            const bots=element('button','pill',botsPending ? 'Bots requested' : 'Add bots');
            bots.type='button'; bots.disabled=botsPending || available===0;
            bots.style.cssText='padding:9px 14px;cursor:pointer;font:inherit';
            const botMessage=element('p','notice',startRequests.get(match.start_token+':bots') ||
                'Choose a bot count. Playlist limit stays '+match.capacity+'. Requires the count-aware game build.');
            botMessage.setAttribute('role','status');
            bots.addEventListener('click',()=>{
                if (!count.reportValidity()) return;
                requestStart(match,bots,botMessage,true,Number(count.value));
            });
            card.append(count,bots,botMessage);
        }
        const teamRoot = element('div','team-grid');
        const assigned = new Set(match.teams.flatMap(team => team.members.map(player => player.name)));
        const unassigned = match.members.filter(player => !assigned.has(player.name));
        const teams = [...match.teams];
        if (unassigned.length) teams.push({label:'Awaiting team assignment',members:unassigned});
        for (const team of teams) {
            const group = element('div','team'); group.append(element('div','team-label',team.label));
            for (const player of team.members) {
                const row = element('div','team-player');
                row.append(element('span','player-name',player.name + (player.host ? ' · Host' : '')));
                if (player.party) row.append(element('span','pill',player.party));
                group.append(row);
            }
            teamRoot.append(group);
        }
        card.append(teamRoot); matchRoot.append(card);
    }
}
function render(s){renderActivity(s.activity);const age=s.uptime_seconds;el('players').textContent=num(s.online_players);el('uptime').textContent=(age>=86400?Math.floor(age/86400)+'d ':'')+Math.floor(age/3600)%24+'h '+Math.floor(age/60)%60+'m';el('tasks').textContent=num(s.tasks);el('packets').textContent=num(s.relay_packets);const fields={'connections':'transport_connections','limit':'connection_limit','logins':'logins','auth':'auth_successes','lobby-auth':'lobby_authentications','frames':'lobby_frames','associations':'relay_associations','verified':'relay_verified','pings':'relay_pings','rejected':'relay_rejected','qos-probes':'qos_probes','nat':'nat_introductions','failures':'lobby_failures'};for(const [id,key] of Object.entries(fields))el(id).textContent=num(s[key]);
if(previous&&age>previous.uptime_seconds&&s.tasks>=previous.tasks){const dt=age-previous.uptime_seconds,rate=(s.tasks-previous.tasks)/dt;history.push(rate);history=history.slice(-60);el('rate').textContent=rate.toFixed(2)+' tasks / second';el('chart-note').textContent='Last '+history.length+' samples · 3-second refresh · this visit';el('cpu').textContent=s.cpu_seconds==null||previous.cpu_seconds==null?'Unavailable':Math.max(0,(s.cpu_seconds-previous.cpu_seconds)/dt*100).toFixed(1)+'%'}else{history=[];el('rate').textContent='Waiting for a second sample';el('cpu').textContent=s.cpu_seconds==null?'Unavailable':'Sampling…';el('chart-note').textContent='History begins when this page opens; samples arrive every 3 seconds.'}previous=s;chart();el('rss').textContent=bytes(s.resident_bytes);el('load').textContent=s.load_1m==null?'Unavailable':s.load_1m.toFixed(2);el('memory').textContent=bytes(s.host_memory_available_bytes)+' / '+bytes(s.host_memory_bytes);el('disk').textContent=bytes(s.disk_available_bytes)+' / '+bytes(s.disk_total_bytes);el('disk-bar').style.width=s.disk_total_bytes?Math.max(0,Math.min(100,100*(1-s.disk_available_bytes/s.disk_total_bytes)))+'%':'0';el('relay').textContent=s.relay_enabled?'Listening':'Unavailable';el('qos').textContent=s.qos_enabled?'Listening':'Unavailable';el('relay-error').textContent=s.relay_failure||'None';el('health').textContent=s.relay_failure||!s.relay_enabled||!s.qos_enabled?'Backend responding · degraded':'Backend responding';el('health').classList.toggle('stale',!!s.relay_failure||!s.relay_enabled||!s.qos_enabled);el('updated').textContent='Updated '+new Date().toLocaleTimeString()+' · every 3 seconds'}
async function refresh(){try{const response=await fetch('/stats.json',{cache:'no-store',signal:AbortSignal.timeout(5000)});if(!response.ok)throw Error('Status unavailable');render(await response.json())}catch(e){previous=null;el('health').textContent='Connection unavailable · data stale';el('health').classList.add('stale');el('updated').textContent='Refresh failed · retrying in 3 seconds'}finally{setTimeout(refresh,3000)}}window.addEventListener('resize',chart);refresh();
</script></body></html>)DASH2";
