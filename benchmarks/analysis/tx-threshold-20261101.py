import json,re,statistics
from pathlib import Path
rows=[]
for label in ('before','t32','t64','t128','after'):
 f=Path(f'artifacts/vrouter/worker-tx-threshold-{label}-raw-20261101.json')
 if not f.exists():continue
 for p in json.loads(f.read_text())['modes'][0]['phases']:
  unique=sum(b['unique'] for b in p['after_receiver']['batches'])-sum(b['unique'] for b in p['before_receiver']['batches'])
  nat=p['after_nat_packets']-p['before_nat_packets'];assert nat==unique
  times=[float(v) for v in re.findall(r'time=([\d.]+) ms',p['gateway_rtt_raw'])]
  maps=[]
  for l in p['worker_samples']['maps'].splitlines():
   if 'librte_net_r8169' in l:
    a,b=l.split()[0].split('-');maps.append((int(a,16),int(b,16)))
  samples=p['worker_samples']['samples'];pmd=sum(any(a<=int(s[0],16)<b for a,b in maps) for s in samples)
  row=dict(version=label,pps=p['pps'],unique=unique,mpps=unique/15e6,rtt_avg_ms=statistics.mean(times),rtt_p95_ms=sorted(times)[int(.95*(len(times)-1))],rtt_received=len(times),rdu=sum(b['rdu_samples'] for b in p['rx_status_samples']['bins']),pmd_sample_percent=100*pmd/len(samples),frequencies=sorted({t['frequency_khz'] for t in p['worker_samples']['telemetry']}))
  rows.append(row)
Path('artifacts/vrouter/tx-threshold-summary-20261101.json').write_text(json.dumps(rows,indent=2)+'\n')
for r in rows:print(r)
