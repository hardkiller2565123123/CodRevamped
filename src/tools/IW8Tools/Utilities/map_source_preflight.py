#!/usr/bin/env python3
"""Offline structural preflight for CodRevamped IW8Tools native map source.

Does not compile .ff files, run Replay, verify proprietary shader bytecode,
or claim engine compatibility. Usage:
  python map_source_preflight.py C:/Maps/mp_crtest [--json report.json]
"""
from __future__ import annotations

import argparse
import json
import math
import re
import struct
from pathlib import Path

MAP_ID = re.compile(r"mp_[a-z0-9_]{1,12}\Z")
NEEDED = {"info_player_start", "mp_tdm_spawn",
          "mp_tdm_spawn_allies_start", "mp_tdm_spawn_axis_start"}


class PreflightError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PreflightError(message)


def read_json(path: Path):
    require(path.is_file(), f"Missing {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def finite(numbers, name):
    require(all(isinstance(x, (int, float)) and math.isfinite(x) for x in numbers),
            name + " contains invalid numbers")


def decompress_normal(value):
    """Same Dec3n quaternion representation used by MW120R's Replay compiler."""
    require(isinstance(value, int) and 0 <= value <= 0xffffffff,
            "Packed frame outside uint32")
    nlargest = value >> 30
    q = [((value & 1023)/1023 * 2 - 1) / math.sqrt(2),
         (((value >> 10) & 1023)/1023 * 2 - 1) / math.sqrt(2),
         (((value >> 20) & 511)/511 * 2 - 1) / math.sqrt(2)]
    q.insert(nlargest, math.sqrt(max(0, 1-sum(v*v for v in q))))
    x, y, z, w = q
    return (2*(x*z+w*y), 2*(y*z-w*x), 1-2*(x*x+y*y))


def inspect_collision(path: Path):
    require(path.is_file(), "Collision source missing (export native graybox)")
    data = path.read_bytes()
    require(len(data) >= 12 and data[:8] == b"MWCOLL02", "Collision must be MWCOLL02")
    count = struct.unpack_from('<I', data, 8)[0]
    require(0 < count <= 600, "Invalid collision hull count")
    offset, verts = 12, 0
    for index in range(count):
        require(len(data) >= offset + 4, f"Truncated collision hull {index}")
        num = struct.unpack_from('<I', data, offset)[0]
        offset += 4
        require(4 <= num <= 128, f"Collision hull {index} has invalid vertex count {num}")
        require(len(data) >= offset + num*12, f"Truncated collision vertices for hull {index}")
        values = struct.unpack_from('<' + 'f'*(num*3), data, offset)
        finite(values, f"Hull {index}")
        require(all(abs(v) <= 100000 for v in values),f"Hull {index} exceeds world coordinate limit")
        offset += num*12
        verts += num
    require(offset == len(data), "Unexpected bytes after collision hulls")
    return {"hulls":count, "vertices":verts, "bytes":len(data)}


def inspect_render(source):
    require(source.get('schema') == 1, "Incorrect render schema")
    surfaces = source.get('surfaces')
    require(isinstance(surfaces, list) and 0 < len(surfaces) <= 4096,
            "Render must contain 1..4096 surfaces")
    triangles = 0
    points = []
    for number, surface in enumerate(surfaces):
        vertices = surface.get('vertices', [])
        indices = surface.get('indices', [])
        require(3 <= len(vertices) <= 60000, f"Surface {number} has invalid vertex count")
        require(len(indices) % 3 == 0 and len(indices) >= 3,
                f"Surface {number} has invalid triangle indices")
        require(all(isinstance(i,int) and 0 <= i < len(vertices) for i in indices),
                f"Surface {number} has an out-of-bounds triangle index")
        local = []
        for vertex in vertices:
            point = vertex.get('position',[])
            uv = vertex.get('uv',[])
            require(len(point)==3 and len(uv)==2, "Wrong position/UV dimensions")
            finite(point, "Position")
            finite(uv, "UV")
            require(all(abs(coord) < 100000 for coord in point),
                    "Vertex outside native world bounds")
            local.append(point)
            points.append(point)
            normal = decompress_normal(vertex.get('normal'))
            finite(normal, "Packed normal")
        # Geometry is authored by convex brush faces. Ensure the serialized
        # packed normal points toward the face's actual geometric normal.
        a,b,c = (local[indices[i]] for i in range(3))
        ab = [b[i]-a[i] for i in range(3)]
        ac = [c[i]-a[i] for i in range(3)]
        cross = [ab[1]*ac[2]-ab[2]*ac[1],
                 ab[2]*ac[0]-ab[0]*ac[2],ab[0]*ac[1]-ab[1]*ac[0]]
        length = math.sqrt(sum(x*x for x in cross))
        require(length>1e-8, f"Surface {number} has a degenerate first triangle")
        n = decompress_normal(vertices[0]['normal'])
        require(sum(cross[i]*n[i] for i in range(3))/length >= .95,
                f"Surface {number} packed normal disagrees with polygon winding")
        triangles+=len(indices)//3
    return {"surfaces":len(surfaces),"triangles":triangles,"vertices":len(points),
            "limits":[[min(p[i] for p in points),max(p[i] for p in points)] for i in range(3)]}


def inspect(project: Path):
    project=project.resolve()
    manifest=read_json(project/'iw8tools.project.json')
    map_id=manifest.get('id','')
    require(bool(MAP_ID.fullmatch(map_id)),"Invalid map ID")
    scene=read_json(project/'source/scene.json')
    spawns=read_json(project/'source/spawns.json')
    require(isinstance(scene,list) and 0<len(scene)<=600,"Expected 1..600 scene brushes")
    require(isinstance(spawns,list) and len(spawns)<=128,"Expected <=128 spawns")
    require(NEEDED.issubset({s.get('Type') for s in spawns}),
            "Missing required TDM spawn classes")
    for spawn in spawns:
        require(spawn.get('Type') in NEEDED,"Unknown TDM spawn class")
        finite([spawn.get(key) for key in ('X','Y','Z','Yaw')],"Spawn")
    dir=project/'dump/maps/mp'
    render=read_json(dir/f'{map_id}.d3dbsp.render.json')
    rendering=inspect_render(render)
    require(render.get('materialDefinition')==f'{map_id}.d3dbsp.material.json',
            "Render material definition mismatch")
    collision=inspect_collision(dir/f'{map_id}.collision.native')
    require(collision['hulls']==len(scene),"Collision and authored scene hull count differ")
    material=read_json(dir/f'{map_id}.d3dbsp.material.json')
    techset=read_json(dir/f'{map_id}.d3dbsp.techset.json')
    require(material.get('techset') == techset.get('name'),
            "Selected material and techset do not match")
    require(bool(techset.get('shaders')) and bool(techset.get('techniques')),
            "A populated Replay 1.20 techset is required")
    images=material.get('imageDefinitions',[])
    for item in images:
        width,height=item.get('width'),item.get('height')
        require(isinstance(width,int) and isinstance(height,int)
                and 0<width<=4096 and 0<height<=4096,"Invalid image dimensions")
        rel=item.get('rgba8','')
        require(isinstance(rel,str) and Path(rel).name==rel and '..' not in rel,
                "Unsafe RGBA image path")
        image=dir/rel
        require(image.is_file() and image.stat().st_size==4*width*height,
                f"Image size mismatch: {rel}")
    entities=project/'dump'/f'{map_id}_iw8_ents.txt'
    require(entities.is_file(),"Missing numeric TDM entity source")
    text=entities.read_text(encoding='utf-8')
    for classname in NEEDED:
        require(f'212 "{classname}"' in text,"Missing exported TDM entity: "+classname)
    bounds=read_json(dir/f'{map_id}.d3dbsp.bounds.json')
    for axis,(vmin,vmax) in enumerate(rendering['limits']):
        require(bounds['min'][axis]<=vmin and bounds['max'][axis]>=vmax,
                "Native bounds exclude render geometry")
    return {"map":map_id,"sourceOnly":True,"nativeCompiled":False,
            "nativeGameLoadVerified":False,"brushes":len(scene),"spawns":len(spawns),
            "render":rendering,"collision":collision,"residentImages":len(images),
            "warnings":["Validating source cannot prove shader compatibility or that Replay will load this map."]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project',type=Path)
    parser.add_argument('--json',dest='output',type=Path)
    args=parser.parse_args()
    try:
        result=inspect(args.project)
        print(json.dumps(result,indent=2))
        if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
        return 0
    except (PreflightError, KeyError, TypeError, ValueError, OSError) as ex:
        print(json.dumps({'ok':False,'error':str(ex)},indent=2))
        return 1

if __name__=='__main__':
    raise SystemExit(main())
