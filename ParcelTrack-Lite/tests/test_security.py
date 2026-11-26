"""End-to-end API security tests; no real consumer data is used."""
import io
import sqlite3
from pathlib import Path
import pytest
from PIL import Image
from fastapi.testclient import TestClient
from api.core import PH, db_connection, utc_now
from api.factory import create_app

KEY = 'test-only-' + 's'*48

@pytest.fixture
def setup(tmp_path):
    app = create_app({'INTERNAL_KEY': KEY,'DATABASE': str(tmp_path/'data.sqlite3'),
                      'UPLOAD_DIR': str(tmp_path/'private-uploads'),'TESTING':True})
    with TestClient(app) as client:
        client.headers.update({'X-Internal-Key':KEY,'X-Client-IP':'192.0.2.15'})
        yield client, str(tmp_path/'data.sqlite3'),tmp_path


def signup(client, email, name='Demo Seller',password='Testing!Secure2026'):
    return client.post('/auth/register',json={'name':name,'email':email,'password':password})


def login(client,email,password='Testing!Secure2026'):
    res=client.post('/auth/login',json={'email':email,'password':password})
    assert res.status_code==200, res.text
    return res.json()['token']


def auth(token): return {'Authorization':'Bearer '+token}


def admin(dbpath,email='admin@example.test'):
    conn=db_connection(dbpath)
    with conn:
        cur=conn.execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',
                         ('Demo Admin', email,PH.hash('Testing!Secure2026'),'admin',utc_now()))
        uid=cur.lastrowid
    conn.close()
    return uid


def make_rider(client,admin_token,email='rider@example.test'):
    res=client.post('/auth/riders',headers=auth(admin_token),json={
        'name':'Demo Rider','email':email,'password':'Testing!Secure2026'})
    assert res.status_code==201,res.text
    return res.json()['user_id']


def parcel(client,seller_token,**overrides):
    body={'recipient_name':'Test Recipient','recipient_phone':'+60123456789',
          'recipient_address':'11 Fictional Street, Sample City', 'weight_kg':'1.250'}
    body.update(overrides)
    return client.post('/parcels',headers=auth(seller_token),json=body)


def png_file():
    output=io.BytesIO()
    Image.new('RGB',(20,20),'white').save(output,format='PNG')
    return output.getvalue()


def seed(setup):
    client, dbpath, _=setup
    assert signup(client,'s1@example.test').status_code==201
    assert signup(client,'s2@example.test').status_code==201
    admin(dbpath)
    t1=login(client,'s1@example.test')
    t2=login(client,'s2@example.test')
    ta=login(client,'admin@example.test')
    rid=make_rider(client,ta)
    tr=login(client,'rider@example.test')
    return client,dbpath,t1,t2,ta,rid,tr


def test_internal_api_requires_shared_key(setup):
    client,_,_=setup
    res=client.get('/auth/me',headers={'X-Internal-Key':'wrong'})
    assert res.status_code==403


def test_password_policy_hash_and_sql_injection_login(setup):
    client,dbpath,_=setup
    assert signup(client,'bad@example.test',password='short').status_code==400
    assert signup(client,'good@example.test').status_code==201
    conn=db_connection(dbpath)
    data=conn.execute('SELECT password_hash FROM users WHERE email=?',('good@example.test',)).fetchone()
    assert data['password_hash'].startswith('$argon2')
    assert 'Testing!Secure2026' not in data['password_hash']
    conn.close()
    attack=client.post('/auth/login',json={'email':"' OR 1=1 --@example.test",'password':'x'})
    assert attack.status_code in (400,401)


def test_account_lockout_and_admin_role_check(setup):
    client,dbpath,_=setup
    signup(client,'good@example.test'); admin(dbpath)
    for i in range(5):
        assert client.post('/auth/login',json={'email':'good@example.test','password':'wrong'}).status_code==401
    assert client.post('/auth/login',json={'email':'good@example.test',
        'password':'Testing!Secure2026'}).status_code==401
    seller=signup(client,'other@example.test'); assert seller.status_code==201
    tok=login(client,'other@example.test')
    assert client.get('/admin/dashboard',headers=auth(tok)).status_code==403


def test_seller_ownership_and_parameterized_search(setup):
    client,_,s1,s2,_,_,_=seed(setup)
    created=parcel(client,s1,recipient_name='<script>alert(1)</script>')
    assert created.status_code==201
    pid=created.json()['parcel_id']
    detail=client.get(f'/parcels/{pid}',headers=auth(s1)).json()
    assert detail['parcel']['recipient_name']=='<script>alert(1)</script>'
    assert client.get(f'/parcels/{pid}',headers=auth(s2)).status_code==404
    assert client.get('/parcels',params={'search':"' OR 1=1 --"},headers=auth(s2)).json()['parcels']==[]
    assert client.post('/parcels',headers=auth(s2),json={'recipient_name':'x'}).status_code==422


def test_invalid_phone_weights_address(setup):
    client,_,s1,_,_,_,_=seed(setup)
    assert parcel(client,s1,recipient_phone='abc123').status_code==400
    assert parcel(client,s1,weight_kg='-5').status_code==400
    assert parcel(client,s1,weight_kg='1 OR 1=1').status_code==400
    assert parcel(client,s1,recipient_address='a'*251).status_code==400


def test_random_track_number_public_privacy_and_injection(setup):
    client,_,s1,_,_,_,_=seed(setup)
    p=parcel(client,s1);assert p.status_code==201
    track=p.json()['tracking_number']
    assert len(track)==27 and track.startswith('PT-')
    res=client.get('/public/track/'+track)
    assert res.status_code==200
    serialized=res.text
    for private in ('recipient','phone','address','seller_id','parcel_id','Test Recipient'):
        assert private not in serialized
    assert res.json()['history'][0]['status']=='Registered'
    assert client.get('/public/track/PT-INVALID').status_code==404
    assert client.get('/public/track/%27%20OR%201=1%20--').status_code==404


def test_public_lookup_rate_limit(setup):
    client,_,_=setup
    for _ in range(20): assert client.get('/public/track/PT-INVALID').status_code==404
    assert client.get('/public/track/PT-INVALID').status_code==429


def test_rider_restrictions_assignment_and_dashboard(setup):
    client,_,s1,s2,ta,rid,tr=seed(setup)
    a=parcel(client,s1).json()['parcel_id'];b=parcel(client,s2).json()['parcel_id']
    assert client.post(f'/admin/parcels/{a}/assign',json={'rider_id':rid},headers=auth(tr)).status_code==403
    assert client.post(f'/admin/parcels/{a}/assign',json={'rider_id':rid},headers=auth(ta)).status_code==200
    ridlist=client.get('/rider/parcels',headers=auth(tr)).json()['parcels']
    assert [p['id'] for p in ridlist]==[a]
    assert client.get(f'/parcels/{b}',headers=auth(tr)).status_code==404
    assert client.get('/admin/dashboard',headers=auth(tr)).status_code==403
    summary=client.get('/admin/dashboard',headers=auth(ta)).json()
    assert summary['counts']['Assigned']==1 and summary['counts']['Registered']==1


def test_status_requires_assignment_transition_and_image(setup):
    client,dbpath,s1,_,ta,rid,tr=seed(setup)
    a=parcel(client,s1).json()['parcel_id']
    assert client.post(f'/rider/parcels/{a}/status',headers=auth(tr),data={'status':'Out for Delivery'}).status_code==404
    client.post(f'/admin/parcels/{a}/assign',json={'rider_id':rid},headers=auth(ta))
    assert client.post(f'/rider/parcels/{a}/status',headers=auth(tr),data={'status':'Alien Status'}).status_code==400
    assert client.post(f'/rider/parcels/{a}/status',headers=auth(tr),data={'status':'Delivered'}).status_code==409
    assert client.post(f'/rider/parcels/{a}/status',headers=auth(tr),data={'status':'Out for Delivery'}).status_code==200
    assert client.post(f'/rider/parcels/{a}/status',headers=auth(tr),data={'status':'Delivered'}).status_code==400
    badfile=client.post(f'/rider/parcels/{a}/status',headers=auth(tr),data={'status':'Delivered'},
             files={'proof':('shell.php.jpg',png_file(),'image/jpeg')})
    assert badfile.status_code==400
    disguise=client.post(f'/rider/parcels/{a}/status',headers=auth(tr),data={'status':'Delivered'},
             files={'proof':('proof.jpg',b'<?php echo 1;?>','image/jpeg')})
    assert disguise.status_code==400
    oversized=client.post(f'/rider/parcels/{a}/status',headers=auth(tr),data={'status':'Delivered'},
             files={'proof':('proof.png',b'x'*(3*1024*1024+1),'image/png')})
    assert oversized.status_code==413
    good=client.post(f'/rider/parcels/{a}/status',headers=auth(tr),data={'status':'Delivered'},
             files={'proof':('proof.png',png_file(),'image/png')})
    assert good.status_code==200,good.text
    assert client.get(f'/parcels/{a}/proof',headers=auth(tr)).status_code==200
    assert client.get(f'/parcels/{a}/proof').status_code==401
    detail=client.get(f'/parcels/{a}',headers=auth(s1)).json()
    assert [x['status'] for x in detail['history']]==['Registered','Assigned','Out for Delivery','Delivered']
    conn=db_connection(dbpath)
    events=[r['event'] for r in conn.execute('SELECT event FROM audit_logs')]
    assert 'status_delivered' in events and 'login_success' in events
    conn.close()


def test_disable_rider_revokes_sessions(setup):
    client,_,s1,_,ta,rid,tr=seed(setup)
    assert client.post(f'/auth/riders/{rid}/disable',headers=auth(ta)).status_code==200
    assert client.get('/rider/parcels',headers=auth(tr)).status_code==401


def test_change_password_revokes_previous_tokens(setup):
    client,_,_=setup
    signup(client,'test@example.test')
    t=login(client,'test@example.test')
    assert client.post('/auth/change-password',headers=auth(t),json={
        'current_password':'Testing!Secure2026','new_password':'Another!Secure2026'}).status_code==200
    assert client.get('/auth/me',headers=auth(t)).status_code==401
    assert login(client,'test@example.test','different-secure-password')


def test_logout_revokes_token(setup):
    client,_,_=setup
    signup(client,'logout@example.test')
    t=login(client,'logout@example.test')
    assert client.post('/auth/logout',headers=auth(t)).status_code==200
    assert client.get('/auth/me',headers=auth(t)).status_code==401


def test_retention_anonymizes_closed_parcels(setup):
    import os
    import subprocess
    import sys
    from datetime import datetime, timezone
    from dateutil.relativedelta import relativedelta
    client,dbpath,s1,_,ta,rid,tr=seed(setup)
    pid=parcel(client,s1).json()['parcel_id']
    client.post(f'/admin/parcels/{pid}/assign',headers=auth(ta),json={'rider_id':rid})
    client.post(f'/rider/parcels/{pid}/status',headers=auth(tr),data={'status':'Out for Delivery'})
    client.post(f'/rider/parcels/{pid}/status',headers=auth(tr),data={'status':'Delivered'},
                files={'proof':('proof.png',png_file(),'image/png')})
    conn=db_connection(dbpath)
    old=(datetime.now(timezone.utc)-relativedelta(months=13)).isoformat(timespec='seconds')
    with conn:
        conn.execute('UPDATE parcels SET closed_at=? WHERE id=?',(old,pid))
    proof_path=Path(conn.execute('SELECT proof_path FROM parcels WHERE id=?',(pid,)).fetchone()['proof_path'])
    assert proof_path.exists()
    conn.close()
    env={**os.environ,'PARCELTRACK_DB_PATH':dbpath}
    run=subprocess.run([sys.executable,'-m','api.cli','anonymize'],env=env,
                       capture_output=True,text=True,check=True)
    assert 'Anonymized 1' in run.stdout
    conn=db_connection(dbpath)
    row=conn.execute('SELECT recipient_name,recipient_address,proof_path FROM parcels WHERE id=?',(pid,)).fetchone()
    assert row['recipient_name']==row['recipient_address']=='[anonymized]'
    assert row['proof_path'] is None and not proof_path.exists()
    conn.close()


@pytest.mark.parametrize('weak_password', [
    '123456789012', 'password1234!', 'aaaaaaaaaaaa',
    'alllowercaseonly', 'Admin@123456', 'qwertyuiop123!'
])
def test_rejects_weak_password_during_seller_registration(setup, weak_password):
    client, _, _ = setup
    res = signup(client, 'weak@example.test', password=weak_password)
    assert res.status_code == 400


def test_accepts_strong_password_and_passphrase(setup):
    client, _, _ = setup
    assert signup(client, 'strong@example.test', password='Lowercase!123').status_code == 201
    assert signup(client, 'passphrase@example.test', password='Purple railway lantern ocean drift').status_code == 201


def test_admin_cli_reprompts_for_weak_password_and_mismatch(tmp_path, monkeypatch, capsys):
    from api.cli import main
    import api.cli as cli
    import builtins
    import sys
    dbpath = tmp_path / 'admin-cli.sqlite3'
    monkeypatch.setenv('PARCELTRACK_DB_PATH', str(dbpath))
    monkeypatch.setattr(sys, 'argv', ['api.cli', 'create-admin'])
    entered = iter(['Demo Admin', 'admin-cli@example.test'])
    monkeypatch.setattr(builtins, 'input', lambda prompt='': next(entered))
    entered_passwords = iter(['password1234!', 'Testing!Secure2026', 'different',
                              'Testing!Secure2026', 'Testing!Secure2026'])
    monkeypatch.setattr(cli.getpass, 'getpass', lambda prompt='': next(entered_passwords))
    main()
    out = capsys.readouterr().out
    assert 'Password rejected:' in out and 'Passwords do not match.' in out
    assert 'Admin created.' in out
    conn = db_connection(str(dbpath))
    record = conn.execute('SELECT role,password_hash FROM users WHERE email=?',
                          ('admin-cli@example.test',)).fetchone()
    assert record['role'] == 'admin'
    assert PH.verify(record['password_hash'], 'Testing!Secure2026')
    conn.close()


def test_shared_password_policy_for_riders_and_changes(setup):
    client, dbpath, _ = setup
    admin(dbpath)
    atoken = login(client, 'admin@example.test')
    rejected = client.post('/auth/riders', headers=auth(atoken), json={
        'name':'Demo Rider','email':'weak-rider@example.test','password':'Password1234!'})
    assert rejected.status_code == 400
    seller = signup(client, 'seller-change@example.test')
    assert seller.status_code == 201
    stoken = login(client, 'seller-change@example.test')
    rejected = client.post('/auth/change-password',headers=auth(stoken),json={
        'current_password':'Testing!Secure2026','new_password':'123456789012'})
    assert rejected.status_code == 400
