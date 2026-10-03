"""Linux-only integration test; pass a native Linux panel binary as the argument."""
import pathlib,tempfile,subprocess,shutil,socket,time,os,threading,json
import sys
def main(panel):
 root=pathlib.Path(__file__).resolve().parents[1]
 with tempfile.TemporaryDirectory(prefix='m2-web-test-') as tmp:
  home=pathlib.Path(tmp);base=home/'data';base.mkdir();runtime=home/'run';runtime.mkdir()
  with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
  def transformed(name):
   return (root/'webpanel'/name).read_text().replace('/data/aqara-panel',str(base)).replace('/var/run',str(runtime)).replace('-listen :80',f'-listen 127.0.0.1:{port}').replace('http://127.0.0.1/api/status',f'http://127.0.0.1:{port}/api/status').replace('sleep 2','sleep 0.2')
  script=transformed('autostart.sh');worker=transformed('update-worker.sh')
  shutil.copyfile(panel,base/'panel');(base/'panel').chmod(0o700)
  subprocess.run([str(base/'panel'),'-data',str(base),'-init','127.0.0.1'],check=True,stdout=subprocess.DEVNULL)
  (base/'autostart.sh').write_text(script)
  auth=(base/'auth.sha256').read_bytes()
  service=subprocess.Popen(['sh',str(base/'autostart.sh')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  threading.Thread(target=service.wait,daemon=True).start();time.sleep(1)
  def stage(bad=False):
   d=base/'.web-update';d.mkdir();shutil.copyfile(panel,d/'panel');(d/'panel').chmod(0o700)
   if bad:(d/'panel').write_text('#!/bin/sh\nexit 13\n')
   (d/'autostart.sh').write_text(script);(d/'worker.sh').write_text(worker);(d/'transaction').touch();return d
  try:
   d=stage();r=subprocess.run(['sh',str(d/'worker.sh')],capture_output=True,text=True,timeout=65)
   assert r.returncode==0,(r.stdout,r.stderr)
   assert json.loads((base/'update-result.json').read_text())['status']=='success'
   assert (base/'auth.sha256').read_bytes()==auth
   print('PASS success, original identity preserved',flush=True)
   d=stage(True);r=subprocess.run(['sh',str(d/'worker.sh')],capture_output=True,text=True,timeout=65)
   assert json.loads((base/'update-result.json').read_text())['status']=='rolled_back',(r.stdout,r.stderr)
   assert (base/'auth.sha256').read_bytes()==auth
   time.sleep(1)
   print('PASS failed-start rollback',flush=True)
   # Simulate interrupted transaction with old panel in backup and bad new one installed.
   (base/'autostart.disabled').touch();pid=int((runtime/'aqara-panel-supervisor/pid').read_text());os.kill(pid,15);time.sleep(2)
   d=stage(True);backup=base/'web-previous';backup.mkdir(exist_ok=True)
   (base/'panel').rename(backup/'panel');shutil.copyfile(base/'autostart.sh',backup/'autostart.sh');(backup/'armed').touch()
   (d/'panel').rename(base/'panel')
   r=subprocess.run(['sh',str(d/'worker.sh'),'--recover'],capture_output=True,text=True,timeout=30)
   assert r.returncode==0,(r.stdout,r.stderr)
   assert not (base/'autostart.disabled').exists();assert (base/'panel').read_bytes()==(panel).read_bytes()
   print('PASS interrupted-transaction recovery',flush=True)
  finally:
   (base/'autostart.disabled').touch()
   pidfile=runtime/'aqara-panel-supervisor/pid'
   if pidfile.exists():
    try:os.kill(int(pidfile.read_text()),15)
    except ProcessLookupError:pass
   time.sleep(2)

if __name__ == "__main__":
 main(pathlib.Path(sys.argv[1]).resolve())
