"""Portable source validator tests, no native game or .NET SDK required."""
import importlib.util
import json
import struct
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'Utilities/map_source_preflight.py'
spec = importlib.util.spec_from_file_location('preflight',SCRIPT)
pf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pf)


def make_project(path):
    (path/'source').mkdir()
    dir = path/'dump/maps/mp'
    dir.mkdir(parents=True)
    json.dump({'id':'mp_crtest'},(path/'iw8tools.project.json').open('w'))
    json.dump([{'Name':'Cube'}],(path/'source/scene.json').open('w'))
    json.dump([{'Type':name,'X':0,'Y':0,'Z':96,'Yaw':0} for name in pf.NEEDED],
              (path/'source/spawns.json').open('w'))
    vertices = [
        {'position':[0,0,0],'uv':[0,0],'normal':0,'color':[255]*4},
        {'position':[1,0,0],'uv':[1,0],'normal':0,'color':[255]*4},
        {'position':[0,1,0],'uv':[0,1],'normal':0,'color':[255]*4}
    ]
    # tangent X, normal Z -> quaternion identity: packed quantization around zero
    # Pack using reference algorithm (largest W=3 and all other components 0).
    packed=511 | (511<<10) | (255<<20) | (3<<30)
    for v in vertices:v['normal']=packed
    json.dump({'schema':1,'materialDefinition':'mp_crtest.d3dbsp.material.json',
               'surfaces':[{'vertices':vertices,'indices':[0,1,2]}]},
              (dir/'mp_crtest.d3dbsp.render.json').open('w'))
    json.dump({'min':[-1,-1,-1],'max':[2,2,2]},
              (dir/'mp_crtest.d3dbsp.bounds.json').open('w'))
    json.dump({'techset':'tw/test','imageDefinitions':[], 'textures':[{'image':'$gray'}]},
              (dir/'mp_crtest.d3dbsp.material.json').open('w'))
    json.dump({'name':'tw/test','shaders':{'a':{'program':'01'}},'techniques':[{'name':'test'}]},
              (dir/'mp_crtest.d3dbsp.techset.json').open('w'))
    with (dir/'mp_crtest.collision.native').open('wb') as writer:
        writer.write(b'MWCOLL02'+struct.pack('<II',1,4))
        for p in [(0,0,0),(1,0,0),(0,1,0),(0,0,1)]:writer.write(struct.pack('<fff',*p))
    (path/'dump/mp_crtest_iw8_ents.txt').write_text(''.join(f'{{ 212 "{name}" }}\n' for name in pf.NEEDED))
    return dir


def test_valid_structural_fixture():
    with TemporaryDirectory() as folder:
        path=Path(folder)
        make_project(path)
        result=pf.inspect(path)
        assert result['nativeGameLoadVerified'] is False
        assert result['collision']['hulls']==1
        assert result['render']['triangles']==1


def test_corrupted_collision_rejected():
    with TemporaryDirectory() as folder:
        path=Path(folder)
        dir=make_project(path)
        (dir/'mp_crtest.collision.native').write_bytes(b'MWCOLL02'+struct.pack('<II',1,4))
        with pytest.raises(pf.PreflightError,match='Truncated'):
            pf.inspect(path)


def test_mispacked_normal_rejected():
    with TemporaryDirectory() as folder:
        path=Path(folder)
        dir=make_project(path)
        src=dir/'mp_crtest.d3dbsp.render.json'
        doc=json.loads(src.read_text())
        for v in doc['surfaces'][0]['vertices']:v['normal']=0
        src.write_text(json.dumps(doc))
        with pytest.raises(pf.PreflightError,match='packed normal'):
            pf.inspect(path)


def test_missing_required_spawn_rejected():
    with TemporaryDirectory() as folder:
        path=Path(folder)
        make_project(path)
        doc=json.loads((path/'source/spawns.json').read_text())
        doc.pop()
        (path/'source/spawns.json').write_text(json.dumps(doc))
        with pytest.raises(pf.PreflightError,match='required TDM'):
            pf.inspect(path)
